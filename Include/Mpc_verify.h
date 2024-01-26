/*******************************************************************************
 * File:        Mpc_verify.cpp
 * Description: Code for verifying an MPC signature, where possible using
 *              code from picnic
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



#ifndef MPC_VERIFY_H
#define MPC_VERIFY_H

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

//#include "Mpc_lowmc.h"
#include "Lowmc64.h"
#include "Mpc_working_data.h"
#include "Mpc_signature_utils.h"
#include "Mpc_seeds_and_tapes.h"

template<typename MC, typename STATE_PTR>
int verify_mpc_signature(MC &mpc_class,
  const uint8_t *signature,
  size_t signature_len,
  uint8_t const *message_digest,
  uint8_t const *nonce,
  STATE_PTR expected_output_ptr) noexcept
{
    Signature_data sig_data{ MC::mpc_param_ };
    if (!sig_data.is_initialised_) {
        std::cerr << "Failed to initialise the signature data\n";
    }

    int ret = sig_data.deserialise_signature(signature, signature_len);
    if (ret != EXIT_SUCCESS) {
        std::cerr << "Failed to deserialize signature\n";
        return EXIT_FAILURE;
    }
    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);

    //=========================================================================
    // Set up the structures and offsets
    Tape_offset next_offset = 0;

    next_offset = mpc_class.set_offsets(next_offset);

    size_t tape_size_bytes = (next_offset + 7U) / 8U;

    //=========================================================================
    // Set up the tapes and seeds

    Verification_seeds_and_tapes s_and_t(tape_size_bytes, sig_data);
    if (!s_and_t.is_initialised_) {
        std::cerr << "Unable to intialise the tapes and seeds\n";
        return EXIT_FAILURE;
    }

    randomTape_t *tapes = s_and_t.tapes_;
    tree_t **seeds = s_and_t.seeds_;

    //=========================================================================
    // Calculate committed values for comparison
    Commitment_data1 commitment_data1;
    if (!commitment_data1.is_initialised) {
        std::cerr << "Unable to setup the initial commitment data\n";
        return EXIT_FAILURE;
    }
    commitments_t *C = commitment_data1.C_;

    uint32_t last = paramset.numMPCParties - 1U;
    auto auxBits =
      static_cast<uint8_t *>(calloc(sig_data.proof_param_.aux_size_bytes_, 1));
    if (auxBits == nullptr) {
        std::cerr << "Unable to allocate memory for the aux bits\n";
        return EXIT_FAILURE;
    }
    // Ensure that auxBits is freed
    std::unique_ptr<uint8_t, decltype(&::free)> aux_bits_ptr(auxBits, ::free);
    for (uint16_t t = 0; t < paramset.numMPCRounds; t++) {

        if (!contains(
              sig_data.mpc_pd_.challengeC_, paramset.numOpenedRounds, t)) {
            //=================================================================
            // We're given iSeed, have expanded the seeds, compute aux
            // from scratch so we can compute Com[t]
            for (uint16_t j = 0; j < last; j++) {
                commit_c(C[t].hashes[j],
                  getLeaf(seeds[t], j),
                  nullptr,
                  sig_data.mpc_pd_.salt_,
                  t,
                  j,
                  &paramset);
            }
            mpc_class.compute_aux_tape_verify(tapes, sig_data, t);
            mpc_class.get_aux_bits(auxBits, tapes, t);
            commit_c(C[t].hashes[last],
              getLeaf(seeds[t], last),
              auxBits,
              sig_data.mpc_pd_.salt_,
              t,
              (uint16_t)last,
              &paramset);
        } else {
            //=================================================================
            // We're given all seeds and aux bits, except for the unopened
            // party, we get their commitment
            size_t unopened = sig_data.mpc_pd_.challengeP_[indexOf(
              sig_data.mpc_pd_.challengeC_, paramset.numOpenedRounds, t)];
            for (uint16_t j = 0; j < last; j++) {
                if (j != unopened) {
                    commit_c(C[t].hashes[j],
                      getLeaf(seeds[t], j),
                      NULL,
                      sig_data.mpc_pd_.salt_,
                      t,
                      j,
                      &paramset);
                }
            }
            //=================================================================
            // For the unopened party we get the aux bits from the signature,
            // provided the unopened party is not the last one.
            if (last != unopened) {
                commit_c(C[t].hashes[last], getLeaf(seeds[t], last),
                  sig_data.proofs_[t]->aux_, sig_data.mpc_pd_.salt_, t,
                  (uint16_t)last, &paramset);
            }
            memcpy(C[t].hashes[unopened], sig_data.proofs_[t]->C_,
              paramset.digestSizeBytes);
        }
    }

    //=========================================================================
    // Commit to the commitments and views
    Commitment_data2 commitments2;
    if (!commitments2.is_initialised) {
        std::cerr
          << "Failed to initialise the data for commitments and views\n ";
        return EXIT_FAILURE;
    }

    for (size_t t = 0; t < paramset.numMPCRounds; t++) {
        commit_h(commitments2.Ch.hashes[t], &C[t], &paramset);
    }

    msgs_t *msgs =
      allocate_msgs(&paramset, sig_data.proof_param_.aux_size_bytes_);
    Msgs_ptr msgs_ptr(msgs, free_msgs);

    shares_t *tmp_shares = allocateShares(paramset.stateSizeBits);
    Shares_ptr tmp_shares_ptr(tmp_shares, freeShares);

    for (size_t t = 0; t < paramset.numMPCRounds; t++) {
        if (contains(
              sig_data.mpc_pd_.challengeC_, paramset.numOpenedRounds, t)) {
            // When t is in C, we have everything we need to re-compute
            // the view, as an honest signer would. We simulate the MPC with
            // one fewer party; the unopned party's values are all set to
            // zero. The masks are not used in verification, information
            // passed in the signature is used instead (aux, msgs, masked
            // plaintext, ...)
            size_t unopened = sig_data.mpc_pd_.challengeP_[indexOf(
              sig_data.mpc_pd_.challengeC_, paramset.numOpenedRounds, t)];
            if (unopened
                != last) {// sig_data.proofs[t].aux is only set when P_t != N
                mpc_class.set_aux_bits(tapes, sig_data, t);
            }
            memset(tapes[t].tape[unopened], 0, tape_size_bytes);
            memcpy(msgs[t].msgs[unopened], sig_data.proofs_[t]->msgs_,
              sig_data.proof_param_.aux_size_bytes_);
            msgs[t].unopened = (int)unopened;

            int rv = mpc_class.mpc_simulate_and_verify(
              tapes, sig_data, &msgs[t], expected_output_ptr, tmp_shares, t);
            if (rv != 0) {
                std::cerr << "Verification failed for round " << t
                          << ", signature invalid\n";
                return EXIT_FAILURE;
            }

            mpc_class.commit_v_verify(commitments2, sig_data, &msgs[t], t);
        } else {
            commitments2.Cv.hashes[t] = NULL;
        }
    }

    tree_t *treeCv = commitments2.treeCv;
    size_t missingLeavesSize = paramset.numMPCRounds - paramset.numOpenedRounds;
    uint16_t *missingLeaves =
      getMissingLeavesList(sig_data.mpc_pd_.challengeC_, &paramset);
    ret = addMerkleNodes(treeCv, missingLeaves, missingLeavesSize,
      sig_data.mpc_pd_.cvInfo_, sig_data.mpc_pd_.cvInfoLen_);
    free(missingLeaves);
    if (ret != 0) { return EXIT_FAILURE; }

    ret = verifyMerkleTree(
      treeCv, commitments2.Cv.hashes, sig_data.mpc_pd_.salt_, &paramset);
    if (ret != 0) { return EXIT_FAILURE; }

    // Compute the challenge hash
    uint8_t *challengeHash =
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

    // Compare to challenge from signature
    if (memcmp(sig_data.mpc_pd_.challengeHash_, challengeHash,
          paramset.digestSizeBytes)
        != 0) {
        printf("Challenge does not match, signature invalid\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

#endif
