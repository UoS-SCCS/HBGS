/*******************************************************************************
 * File:        Mpc_signature_utils.h
 * Description: Utilities used for MPC signatures
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



#ifndef MPC_SIGNATURE_UTILS_H
#define MPC_SIGNATURE_UTILS_H

#include <iostream>
#include <cmath>
#include <vector>

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}
#include "Mpc_parameters.h"

class Mpc_proof_data
{
  public:
    Mpc_proof_data() noexcept;
    ~Mpc_proof_data();

    bool is_initialised_{ false };
    uint8_t *salt_;
    uint8_t *iSeedInfo_{
        nullptr
    };// Info required to recompute the tree of all initial seeds
    size_t iSeedInfoLen_{ 0 };
    uint8_t *cvInfo_{ nullptr };// Info required to check commitments to views
                                // (reconstruct Merkle tree)
    size_t cvInfoLen_{ 0 };
    uint8_t *challengeHash_{ nullptr };
    uint16_t *challengeC_{ nullptr };
    uint16_t *challengeP_{ nullptr };
};

class Proof2// Derived from picnic proof2_t
{
  public:
    Proof2() = delete;
    Proof2(Mpc_param const &param);
    ~Proof2();

    bool is_initialised_{ false };
    uint8_t *seedInfo_{ nullptr };// Information required to compute the tree
                                  // with seeds of of all opened parties
    size_t seedInfoLen_{ 0 };// Length of seedInfo buffer
    uint8_t *C_{ nullptr };// Commitment to preprocessing step of unopened party
    uint8_t *aux_{
        nullptr
    };// Last party's correction bits; NULL if P[t] == N-1
    uint8_t *msgs_{ nullptr };// Broadcast messages of unopened party P[t]

    std::vector<uint8_t *> inputs_;// Inputs used in online execution
    std::vector<uint8_t *>
      mpc_inputs_;// MPC inputs for LowMC used in online execution
    std::vector<uint8_t *> outputs_;// Outputs from the online
                                    // execution needed for checking
};

class Signature_data
{
  public:
    Signature_data() = delete;
    Signature_data(Mpc_param const &param) noexcept;
    size_t signature_size() const noexcept;
    size_t serialise_signature(uint8_t *signature, size_t signature_len) const
      noexcept;
    int deserialise_signature(
      const uint8_t *signature, size_t signature_len) noexcept;
    ~Signature_data();

    bool is_initialised_{ false };
    Mpc_proof_data mpc_pd_;
    Mpc_param proof_param_{};
    Proof2 **proofs_{ nullptr };
};

size_t signature_size_estimate(
  Mpc_param const &proof_param, paramset_t const &paramset);

#endif
