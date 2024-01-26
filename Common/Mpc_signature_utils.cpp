/*******************************************************************************
 * File:        Mpc_signature_utils.cpp
 * Description: Utilities used for MPC proofs
 *
 * Author:      Chris Newton
 *
 * Created:     Monday 21 February 2022
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



#include <iostream>
#include <cmath>
#include <vector>

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}
#include "Picnic_mpc_functions.h"
#include "Mpc_parameters.h"
#include "Mpc_utils.h"
#include "Mpc_signature_utils.h"

Mpc_proof_data::Mpc_proof_data() noexcept
{
    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);

    salt_ = static_cast<uint8_t *>(malloc(paramset.saltSizeBytes));
    if (salt_ == nullptr) { return; }
    iSeedInfo_ = nullptr;
    iSeedInfoLen_ = 0;
    cvInfo_ = nullptr;// Sign/verify code sets it
    cvInfoLen_ = 0;
    challengeC_ = static_cast<uint16_t *>(
      malloc(paramset.numOpenedRounds * sizeof(uint16_t)));
    if (challengeC_ == nullptr) { return; }
    challengeP_ = static_cast<uint16_t *>(
      malloc(paramset.numOpenedRounds * sizeof(uint16_t)));
    if (challengeP_ == nullptr) { return; }
    challengeHash_ =
      static_cast<uint8_t *>(malloc(Mpc_parameters::challenge_hash_bytes_));
    if (challengeHash_ == nullptr) { return; }

    is_initialised_ = true;
}

Mpc_proof_data::~Mpc_proof_data()
{
    free(salt_);
    free(iSeedInfo_);
    free(cvInfo_);
    free(challengeC_);
    free(challengeP_);
    free(challengeHash_);
}

// Based on picnic proof2_t
Proof2::Proof2(Mpc_param const &param)
{
    // paramset_t paramset;
    // get_param_set(get_picnic_parameter_set_id(), &paramset);
    aux_ = static_cast<uint8_t *>(calloc(1, param.aux_size_bytes_));
    if (aux_ == nullptr) { return; }
    C_ = static_cast<uint8_t *>(malloc(Mpc_parameters::digest_size_bytes_));
    if (C_ == nullptr) { return; }
    msgs_ = static_cast<uint8_t *>(calloc(1, param.aux_size_bytes_));
    if (msgs_ == nullptr) { return; }

    bool allocations_ok{ true };
    inputs_.resize(param.n_inputs_);
    for (size_t i = 0; i < param.n_inputs_; ++i) {
        inputs_[i] =
          static_cast<uint8_t *>(calloc(1, Mpc_parameters::lowmc_state_bytes_));
        if (inputs_[i] == nullptr) {
            allocations_ok = false;
            break;
        }
    }
    if (!allocations_ok) { return; }

    mpc_inputs_.resize(param.n_mpc_inputs_);
    for (size_t i = 0; i < param.n_mpc_inputs_; ++i) {
        mpc_inputs_[i] =
          static_cast<uint8_t *>(calloc(1, Mpc_parameters::lowmc_state_bytes_));
        if (mpc_inputs_[i] == nullptr) {
            allocations_ok = false;
            break;
        }
    }
    if (!allocations_ok) { return; }

    outputs_.resize(param.n_outputs_);
    for (size_t i = 0; i < param.n_outputs_; ++i) {
        outputs_[i] =
          static_cast<uint8_t *>(calloc(1, Mpc_parameters::lowmc_state_bytes_));
        if (outputs_[i] == nullptr) {
            allocations_ok = false;
            break;
        }
    }

    if (!allocations_ok) { return; }

    is_initialised_ = true;
}

Proof2::~Proof2()
{
    free(seedInfo_);
    free(aux_);
    free(C_);
    free(msgs_);

    for (auto &m : inputs_) { free(m); }

    for (auto &m : mpc_inputs_) { free(m); }

    for (auto &m : outputs_) { free(m); }

    is_initialised_ = false;
}

Signature_data::Signature_data(Mpc_param const &param) noexcept
  : proof_param_(param)
{
    if (!mpc_pd_.is_initialised_) { return; }

    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);
    proofs_ = new Proof2 *[paramset.numMPCRounds] { nullptr };
    if (proofs_ == nullptr) { return; }
    // Individual proofs are allocated during signature generation, only for
    // rounds when neeeded

    is_initialised_ = true;
}

Signature_data::~Signature_data()
{
    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);

    for (size_t i = 0; i < paramset.numMPCRounds; i++) {
        if (proofs_[i] != nullptr) { delete proofs_[i]; }
    }

    delete[] proofs_;

    is_initialised_ = false;
}

size_t Signature_data::signature_size() const noexcept
{
    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);

    size_t bytes_required = Mpc_parameters::challenge_hash_bytes_
                            + paramset.saltSizeBytes;// challenge and salt

    bytes_required += mpc_pd_.iSeedInfoLen_;// Encode only iSeedInfo, the length
                                            // will be recomputed by deserialize
    bytes_required += mpc_pd_.cvInfoLen_;

    for (size_t t = 0; t < paramset.numMPCRounds; t++) {// proofs
        if (contains(mpc_pd_.challengeC_, paramset.numOpenedRounds, t)) {
            size_t P_t = mpc_pd_.challengeP_[indexOf(
              mpc_pd_.challengeC_, paramset.numOpenedRounds, t)];
            bytes_required += proofs_[t]->seedInfoLen_;
            if (P_t != (paramset.numMPCParties - 1)) {
                bytes_required += proof_param_.aux_size_bytes_;
            }
            bytes_required += proof_param_.aux_size_bytes_;// For msgs
            bytes_required += proof_param_.n_inputs_ * paramset.stateSizeBytes;
            bytes_required +=
              proof_param_.n_mpc_inputs_ * paramset.stateSizeBytes;
            bytes_required += proof_param_.n_outputs_ * paramset.stateSizeBytes;
            bytes_required += paramset.digestSizeBytes;
        }
    }

    return bytes_required;
}

size_t Signature_data::serialise_signature(
  uint8_t *signature, size_t signature_len_assigned) const noexcept
{
    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);

    if (signature_len_assigned < signature_size()) {
        std::cerr << "serialise_signature: buffer provided is too small\n";
        return 0;
    }

    uint8_t *signature_base = signature;

    memcpy(
      signature, mpc_pd_.challengeHash_, Mpc_parameters::challenge_hash_bytes_);
    signature += Mpc_parameters::challenge_hash_bytes_;

    memcpy(signature, mpc_pd_.salt_, paramset.saltSizeBytes);
    signature += paramset.saltSizeBytes;

    memcpy(signature, mpc_pd_.iSeedInfo_, mpc_pd_.iSeedInfoLen_);
    signature += mpc_pd_.iSeedInfoLen_;

    memcpy(signature, mpc_pd_.cvInfo_, mpc_pd_.cvInfoLen_);
    signature += mpc_pd_.cvInfoLen_;

    // Write the proofs
    for (size_t t = 0; t < paramset.numMPCRounds; t++) {
        if (contains(mpc_pd_.challengeC_, paramset.numOpenedRounds, t)) {
            memcpy(signature, proofs_[t]->seedInfo_, proofs_[t]->seedInfoLen_);
            signature += proofs_[t]->seedInfoLen_;
            size_t P_t = mpc_pd_.challengeP_[indexOf(
              mpc_pd_.challengeC_, paramset.numOpenedRounds, t)];
            if (P_t != (paramset.numMPCParties - 1)) {
                memcpy(
                  signature, proofs_[t]->aux_, proof_param_.aux_size_bytes_);
                signature += proof_param_.aux_size_bytes_;
            }
            memcpy(signature, proofs_[t]->msgs_, proof_param_.aux_size_bytes_);
            signature += proof_param_.aux_size_bytes_;

            for (auto const &m : proofs_[t]->inputs_) {
                memcpy(signature, m, paramset.stateSizeBytes);
                signature += paramset.stateSizeBytes;
            }

            for (auto const &m : proofs_[t]->mpc_inputs_) {
                memcpy(signature, m, paramset.stateSizeBytes);
                signature += paramset.stateSizeBytes;
            }

            for (auto const &m : proofs_[t]->outputs_) {
                memcpy(signature, m, paramset.stateSizeBytes);
                signature += paramset.stateSizeBytes;
            }

            memcpy(signature, proofs_[t]->C_, paramset.digestSizeBytes);
            signature += paramset.digestSizeBytes;
        }
    }

    return static_cast<size_t>(signature - signature_base);
}

int Signature_data::deserialise_signature(
  const uint8_t *signature, size_t signature_len) noexcept
{
    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);

    // Read the challenge and salt
    size_t bytes_required =
      Mpc_parameters::challenge_hash_bytes_ + paramset.saltSizeBytes;

    if (signature_len < bytes_required) { return EXIT_FAILURE; }

    memcpy(
      mpc_pd_.challengeHash_, signature, Mpc_parameters::challenge_hash_bytes_);
    signature += Mpc_parameters::challenge_hash_bytes_;
    memcpy(mpc_pd_.salt_, signature, paramset.saltSizeBytes);
    signature += paramset.saltSizeBytes;

    calculate_challenge_lists(mpc_pd_.challengeHash_, mpc_pd_.challengeC_,
      mpc_pd_.challengeP_, &paramset);

    // Add size of iSeeds tree data
    mpc_pd_.iSeedInfoLen_ = revealSeedsSize(paramset.numMPCRounds,
      mpc_pd_.challengeC_, paramset.numOpenedRounds, &paramset);
    bytes_required += mpc_pd_.iSeedInfoLen_;

    // Add the size of the Cv Merkle tree data
    size_t missingLeavesSize = paramset.numMPCRounds - paramset.numOpenedRounds;
    uint16_t *missingLeaves =
      getMissingLeavesList(mpc_pd_.challengeC_, &paramset);
    mpc_pd_.cvInfoLen_ = openMerkleTreeSize(
      paramset.numMPCRounds, missingLeaves, missingLeavesSize, &paramset);
    bytes_required += mpc_pd_.cvInfoLen_;
    free(missingLeaves);

    // Compute the number of bytes required for the proofs
    uint16_t hideList[1] = { 0 };
    size_t seedInfoLen =
      revealSeedsSize(paramset.numMPCParties, hideList, 1, &paramset);
    for (size_t t = 0; t < paramset.numMPCRounds; t++) {
        if (contains(mpc_pd_.challengeC_, paramset.numOpenedRounds, t)) {
            size_t P_t = mpc_pd_.challengeP_[indexOf(
              mpc_pd_.challengeC_, paramset.numOpenedRounds, t)];
            if (P_t != (paramset.numMPCParties - 1)) {
                bytes_required += proof_param_.aux_size_bytes_;// For aux
            }
            bytes_required += seedInfoLen;
            bytes_required += proof_param_.aux_size_bytes_;// For msgs

            bytes_required +=
              (proof_param_.n_inputs_ + proof_param_.n_mpc_inputs_
                + proof_param_.n_outputs_)
              * paramset.stateSizeBytes;
            bytes_required += paramset.digestSizeBytes;
        }
    }

    // Fail if the signature does not have the exact number of bytes we expect
    if (signature_len != bytes_required) {
        std::cerr << "signature_len = " << signature_len
                  << ", expected bytes_required =" << bytes_required << '\n';
        return EXIT_FAILURE;
    }

    mpc_pd_.iSeedInfo_ = static_cast<uint8_t *>(malloc(mpc_pd_.iSeedInfoLen_));
    memcpy(mpc_pd_.iSeedInfo_, signature, mpc_pd_.iSeedInfoLen_);
    signature += mpc_pd_.iSeedInfoLen_;

    mpc_pd_.cvInfo_ = static_cast<uint8_t *>(malloc(mpc_pd_.cvInfoLen_));
    memcpy(mpc_pd_.cvInfo_, signature, mpc_pd_.cvInfoLen_);
    signature += mpc_pd_.cvInfoLen_;

    // Read the proofs
    for (size_t t = 0; t < paramset.numMPCRounds; t++) {

        if (contains(mpc_pd_.challengeC_, paramset.numOpenedRounds, t)) {
            proofs_[t] = new Proof2(proof_param_);
            proofs_[t]->seedInfoLen_ = seedInfoLen;
            proofs_[t]->seedInfo_ =
              static_cast<uint8_t *>(malloc(proofs_[t]->seedInfoLen_));
            memcpy(proofs_[t]->seedInfo_, signature, proofs_[t]->seedInfoLen_);
            signature += proofs_[t]->seedInfoLen_;

            size_t P_t = mpc_pd_.challengeP_[indexOf(
              mpc_pd_.challengeC_, paramset.numOpenedRounds, t)];
            if (P_t != (paramset.numMPCParties - 1)) {
                memcpy(
                  proofs_[t]->aux_, signature, proof_param_.aux_size_bytes_);
                signature += proof_param_.aux_size_bytes_;
                if (!arePaddingBitsZero(
                      proofs_[t]->aux_, proof_param_.aux_size_bits_)) {
                    std::cerr << "failed while deserializing aux bits\n";
                    return EXIT_FAILURE;
                }
            }
            memcpy(proofs_[t]->msgs_, signature, proof_param_.aux_size_bytes_);
            signature += proof_param_.aux_size_bytes_;
            if (!arePaddingBitsZero(
                  proofs_[t]->msgs_, proof_param_.aux_size_bits_)) {
                std::cerr << "failed while deserializing msgs bits\n";
                return EXIT_FAILURE;
            }

            for (auto &m : proofs_[t]->inputs_) {
                memcpy(m, signature, paramset.stateSizeBytes);
                signature += paramset.stateSizeBytes;
            }

            for (auto &m : proofs_[t]->mpc_inputs_) {
                memcpy(m, signature, paramset.stateSizeBytes);
                signature += paramset.stateSizeBytes;
            }

            for (auto &m : proofs_[t]->outputs_) {
                memcpy(m, signature, paramset.stateSizeBytes);
                signature += paramset.stateSizeBytes;
            }

            memcpy(proofs_[t]->C_, signature, paramset.digestSizeBytes);
            signature += paramset.digestSizeBytes;
        }
    }
    return EXIT_SUCCESS;
}


size_t signature_size_estimate(
  Mpc_param const &proof_param, paramset_t const &paramset)
{
    // Picnic3 parameter sets only
    size_t u = paramset.numOpenedRounds;
    size_t T = paramset.numMPCRounds;
    size_t numTreeValues =
      u * ceil_log2((uint32_t)((T + (u - 1)) / u));// u*ceil(log2(ceil(T/u)))

    size_t proof_size =
      paramset.seedSizeBytes
        * ceil_log2(paramset.numMPCParties)// Info to recompute seeds
      + paramset.digestSizeBytes;// size of commitment of unopened party
    // aux, broadcast messages, mpc_inputs, masked_inputs,
    // masked_outputs
    proof_size += proof_param.aux_size_bytes_;// For aux, this may be
    // an overestimate if one of the challenge parties is the last
    // one
    proof_size += proof_param.aux_size_bytes_;// For msgs
    proof_size += proof_param.n_inputs_ * paramset.stateSizeBytes;
    proof_size += proof_param.n_mpc_inputs_ * paramset.stateSizeBytes;
    proof_size += proof_param.n_outputs_ * paramset.stateSizeBytes;

    size_t signatureSize =
      paramset.saltSizeBytes// salt
      + Mpc_parameters::challenge_hash_bytes_// challenge hash
      + numTreeValues * paramset.seedSizeBytes// iSeed info
      + numTreeValues
          * paramset.digestSizeBytes// commitment opening info for views
      + proof_size * u;// one proof per challenged (opened) execution
    return signatureSize;
}
