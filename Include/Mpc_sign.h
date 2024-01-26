/*******************************************************************************
 * File:        Mpc_sign.h
 * Description: Code for MPC signing, where possible using code from picnic
 *
 * Author:      Chris Newton
 * Created:     5 March 2022
 *
 * (C) Copyright 2022, University of Surrey. All rights reserved.
 *
*******************************************************************************/

/*******************************************************************************
*                                                                              *
* (C) Copyright 2018-2023 University of Surrey. All rights reserved.           *
*                                                                              *
* Redistribution and use in source and binary forms, with or without           *
* modification, are permitted provided that the following conditions are met:  *
*                                                                              *
* 1. Redistributions of source code must retain the above copyright notice,    *
* this list of conditions and the following disclaimer.                        *
*                                                                              *
* 2. Redistributions in binary form must reproduce the above copyright notice, *
* this list of conditions and the following disclaimer in the documentation    *
* and/or other materials provided with the distribution.                       *
*                                                                              *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  *
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    *
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   *
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE    *
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR          *
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF         *
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS     *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN      *
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)      *
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE   *
* POSSIBILITY OF SUCH DAMAGE.                                                  *
*                                                                              *
*******************************************************************************/



#ifndef MPC_SIGN_H
#define MPC_SIGN_H

#include <cmath>
#include <cinttypes>
#include <cstring>
#include <thread>
#include <exception>
#include <iostream>
#include <string>
#include <vector>
#include "Io_utils.h"

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
}

#include "Picnic_mpc_functions.h"
#include "Mpc_utils.h"
#include "Mpc_signature_utils.h"
#include "Mpc_parameters.h"
#include "Mpc_seeds_and_tapes.h"
#include "Mpc_working_data.h"

//#define DEBUG_SIGNING

template<typename T>
int generate_mpc_signature(T &mpc_class,
  uint8_t const *message_digest,
  uint8_t const *nonce,
  Signature_data &sig_data) noexcept
{
    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);

    //=========================================================================
#ifdef DEBUG_SIGNING
    std::cout << "generate_mpc_signature\n";
    print_hbgs_parameters(std::cout);
    std::cout << "\ncompute_salt_and_root_seed\n";
#endif
    auto saltAndRoot = std::make_unique<uint8_t[]>(
      paramset.saltSizeBytes + paramset.seedSizeBytes);
    if (saltAndRoot == nullptr) { return EXIT_FAILURE; }
    uint8_t *salt_and_root = saltAndRoot.get();
    mpc_class.compute_salt_and_root_seed(
      salt_and_root, paramset.saltSizeBytes + paramset.seedSizeBytes, nonce);
    memcpy(sig_data.mpc_pd_.salt_, salt_and_root, paramset.saltSizeBytes);

    tree_t *iSeedsTree = generateSeeds(paramset.numMPCRounds,
      salt_and_root + paramset.saltSizeBytes,
      sig_data.mpc_pd_.salt_,
      0,
      &paramset);
    Tree_ptr iseeds_tree_ptr(iSeedsTree, freeTree);

    //=========================================================================
    // Set up the structures and offsets
#ifdef DEBUG_SIGNING
    std::cout << "set_offsets\n";
#endif
    Tape_offset next_offset = 0;

    next_offset = mpc_class.set_offsets(next_offset);

    size_t tape_size_bytes = (next_offset + 7U) / 8U;
    std::cout << "Tape size bytes: " << tape_size_bytes << '\n';
    //=========================================================================
    // Set up the tapes and seeds. Pass on ownership of iSeedsTree
#ifdef DEBUG_SIGNING
    std::cout << "setup salts and seeds\n";
#endif
    Signing_seeds_and_tapes s_and_t(
      tape_size_bytes, sig_data.mpc_pd_.salt_, iseeds_tree_ptr.release());
    if (!s_and_t.is_initialised) {
        std::cerr << "Unable to initialise the seeds and tapes\n";
        return EXIT_FAILURE;
    }

    randomTape_t *tapes = s_and_t.tapes_;
    tree_t **seeds = s_and_t.seeds_;

    // print_random_tapes(std::cout, tapes, tape_size_bytes);

    Mpc_working_data mpc_wd(sig_data.proof_param_);
    if (!mpc_wd.is_initialised_) {
        std::cerr << "Mpc_working_data not correctly initialised\n";
        return EXIT_FAILURE;
    }

    //=========================================================================
    // Preprocessing; compute aux tape for the N-th player, for each parallel
    // rep
#ifdef DEBUG_SIGNING
    std::cout << "compute_aux_tape_sign\n";
#endif
    for (size_t t = 0; t < paramset.numMPCRounds; t++) {
        mpc_class.compute_aux_tape_sign(tapes, mpc_wd, t);
    }
    //=========================================================================
    // Commit to seeds and aux bits
#ifdef DEBUG_SIGNING
    std::cout << "commit to seeds and aux bits\n";
#endif
    Commitment_data1 commitment_data1;
    if (!commitment_data1.is_initialised) {
        std::cerr << "Unable to setup the initial commitment data\n";
        return EXIT_FAILURE;
    }
    commitments_t *C = commitment_data1.C_;
    for (uint16_t t = 0; t < paramset.numMPCRounds; t++) {
        for (uint16_t j = 0; j < paramset.numMPCParties - 1; j++) {
            commit_c(C[t].hashes[j],
              getLeaf(seeds[t], j),
              NULL,
              sig_data.mpc_pd_.salt_,
              t,
              j,
              &paramset);
        }
        uint32_t last = paramset.numMPCParties - 1;
        mpc_class.get_aux_bits(mpc_wd.aux_bits_, tapes, t);
        commit_c(C[t].hashes[last],
          getLeaf(seeds[t], last),
          mpc_wd.aux_bits_,
          sig_data.mpc_pd_.salt_,
          t,
          (uint16_t)last,
          &paramset);
    }

    //=========================================================================
    // Simulate the online phase of the MPC
    // tmp_shares just used internally - picnic version can be used directly
#ifdef DEBUG_SIGNING
    std::cout << "simulate the online phase of the MPC\n";
#endif
    shares_t *tmp_shares = allocateShares(paramset.stateSizeBits);
    Shares_ptr tmp_shares_ptr(tmp_shares, freeShares);

    int rv{ 0 };
    for (size_t t = 0; t < paramset.numMPCRounds; t++) {
        rv = mpc_class.mpc_simulate_sign(tapes, mpc_wd, tmp_shares, t);
        if (rv != 0) {
            std::cerr << "MPC simulation failed, aborting signature\n";
            return EXIT_FAILURE;
        }
    }

    //=========================================================================
    // Commit to the commitments and views
#ifdef DEBUG_SIGNING
    std::cout << "commit to the commitments and views\n";
#endif
    Commitment_data2 commitments2;
    if (!commitments2.is_initialised) {
        std::cerr
          << "Failed to initialise the data for commitments and views\n";
        return EXIT_FAILURE;
    }

    for (size_t t = 0; t < paramset.numMPCRounds; t++) {
        commit_h(commitments2.Ch.hashes[t], &C[t], &paramset);
        mpc_class.commit_v_sign(commitments2, mpc_wd, t);
    }

    //=========================================================================
    // Create a Merkle tree with Cv as the leaves
#ifdef DEBUG_SIGNING
    std::cout << "compute the Merkle tree\n";
#endif
    buildMerkleTree(commitments2.treeCv,
      commitments2.Cv.hashes,
      sig_data.mpc_pd_.salt_,
      &paramset);

    //=========================================================================
    // Compute the challenge hash
#ifdef DEBUG_SIGNING
    std::cout << "compute the challenge hash\n";
#endif
    auto challengeHash =
      static_cast<uint8_t *>(malloc(Mpc_parameters::challenge_hash_bytes_));
    if (challengeHash == nullptr) {
        std::cerr << "Unable to allocate memory for the challenge hash\n";
        return EXIT_FAILURE;
    }
    // Ensure that challengeHash is freed
    std::unique_ptr<uint8_t, decltype(&::free)> challenge_hash_ptr(
      challengeHash, ::free);

    mpc_class.calculate_hcp(
      challengeHash, sig_data, commitments2, message_digest, nonce);

    // Save the challenge hash
    memcpy(sig_data.mpc_pd_.challengeHash_, challengeHash,
      Mpc_parameters::challenge_hash_bytes_);

    // Obtain the challenge lists
    uint16_t *challengeC = sig_data.mpc_pd_.challengeC_;
    uint16_t *challengeP = sig_data.mpc_pd_.challengeP_;
    calculate_challenge_lists(challengeHash, challengeC, challengeP, &paramset);

    //=========================================================================
    // Generate seed data for verifier
    // Send information required for checking commitments with Merkle tree.
    // The commitments the verifier will be missing are those not in
    // challengeC.   ???????????
#ifdef DEBUG_SIGNING
    std::cout << "generate seed data for the verifier\n";
#endif
    size_t missingLeavesSize = paramset.numMPCRounds - paramset.numOpenedRounds;
    uint16_t *missingLeaves = getMissingLeavesList(challengeC, &paramset);
    size_t cvInfoLen = 0;
    uint8_t *cvInfo = openMerkleTree(
      commitments2.treeCv, missingLeaves, missingLeavesSize, &cvInfoLen);
    sig_data.mpc_pd_.cvInfo_ = cvInfo;
    sig_data.mpc_pd_.cvInfoLen_ = cvInfoLen;
    free(missingLeaves);

    // Reveal iSeeds for unopened rounds, those in {0..T-1} \ ChallengeC.
    sig_data.mpc_pd_.iSeedInfo_ = static_cast<uint8_t *>(
      malloc(paramset.numMPCRounds * paramset.seedSizeBytes));
    sig_data.mpc_pd_.iSeedInfoLen_ = revealSeeds(iSeedsTree,
      challengeC,
      paramset.numOpenedRounds,
      sig_data.mpc_pd_.iSeedInfo_,
      paramset.numMPCRounds * paramset.seedSizeBytes,
      &paramset);
    sig_data.mpc_pd_.iSeedInfo_ = static_cast<uint8_t *>(
      realloc(sig_data.mpc_pd_.iSeedInfo_, sig_data.mpc_pd_.iSeedInfoLen_));
    //=========================================================================
#ifdef DEBUG_SIGNING
    std::cout << "assembling the proof\n" << std::flush;
#endif
    // Assemble the proof
    Proof2 **proofs = sig_data.proofs_;
    for (size_t t = 0; t < paramset.numMPCRounds; t++) {
        if (contains(challengeC, paramset.numOpenedRounds, t)) {
            //=================================================================
            // Save proof data for this opened round - first allocate memory
            proofs[t] = new Proof2(sig_data.proof_param_);
            int P_index = indexOf(challengeC, paramset.numOpenedRounds, t);
            //=================================================================
            // Include seed information for this opened round
            uint16_t hideList[1];
            hideList[0] = challengeP[P_index];
            proofs[t]->seedInfo_ = static_cast<uint8_t *>(
              malloc(paramset.numMPCParties * paramset.seedSizeBytes));
            proofs[t]->seedInfoLen_ = revealSeeds(seeds[t],
              hideList,
              1,
              proofs[t]->seedInfo_,
              paramset.numMPCParties * paramset.seedSizeBytes,
              &paramset);
            proofs[t]->seedInfo_ = static_cast<uint8_t *>(
              realloc(proofs[t]->seedInfo_, proofs[t]->seedInfoLen_));
            //=================================================================
            // Save the C hash
            memcpy(proofs[t]->C_,
              C[t].hashes[challengeP[P_index]],
              paramset.digestSizeBytes);
            //=================================================================
            // Save the aux bits
            size_t last = paramset.numMPCParties - 1;
            if (challengeP[P_index] != last) {// Needs update for other cases
                mpc_class.get_aux_bits(proofs[t]->aux_, tapes, t);
            }
            //=================================================================
            // Save the other data needed for the verifier to check this opened
            // round
            memcpy(proofs[t]->msgs_,
              mpc_wd.msgs_[t].msgs[challengeP[P_index]],
              sig_data.proof_param_.aux_size_bytes_);

            mpc_class.save_proof_data(proofs[t], mpc_wd, t);
        }
    }

    return EXIT_SUCCESS;
}

#endif
