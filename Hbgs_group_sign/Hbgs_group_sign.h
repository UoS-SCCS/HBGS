/*******************************************************************************
 * File:        Hbgs_group_sign.cpp
 * Description: Code to test the SPHINCS+ tree's authpaths. It reads an
 *              authpaths file, amd signs using one of the tree's paths
 *
 * Author:      Chris Newton
 * Created:     Wednesday 27 July 2022
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



#ifndef HBGS_MFORS_SIGNING_H
#define HBGS_MFORS_SIGNING_H

#include <iostream>
#include <string>

#include "Clock_utils.h"
#include "Hbgs_issuer.h"
#include "Hbgs_param.h"
#include "Mpc_working_data.h"
#include "Mpc_signature_utils.h"
#include "Mpc_parameters.h"
#include "Group_authpaths.h"
#include "Mfors_tree.h"
#include "Mpc_mfors_authpath.h"
#include "Mpc_mfors_full_paths.h"

void usage(std::ostream &os, std::string program);


class Mpc_group_sign
{
  public:
    Mpc_group_sign() = delete;
    Mpc_group_sign(Group_authpaths_ptr group_paths_ptr) noexcept;
    Tape_offset set_offsets(Tape_offset const &of) noexcept;
    void compute_salt_and_root_seed(uint8_t *salt_and_root, size_t s_and_r_len,
      uint8_t const *nonce) noexcept;
    void compute_aux_tape_sign(
      randomTape_t *tapes, Mpc_working_data &mpc_wd, size_t t) noexcept;
    void compute_aux_tape_verify(randomTape_t *tapes,
      [[maybe_unused]] Signature_data const &sig_data, size_t t) noexcept;
    void get_aux_bits(
      uint8_t *aux_bits, randomTape_t *tapes, size_t t) noexcept;
    void set_aux_bits(
      randomTape_t *tapes, Signature_data const &sig_data, size_t t) noexcept;
    int mpc_simulate_sign(randomTape_t *tapes, Mpc_working_data &mpc_wd,
      shares_t *tmp_shares, size_t t) noexcept;
    void commit_v_sign(
      Commitment_data2 &c2, Mpc_working_data const &wd, size_t t);
    void commit_v_verify(Commitment_data2 &c2, Signature_data const &sig_data,
      msgs_t const *msgs, size_t t);
    void calculate_hcp(uint8_t *challenge_hash, Signature_data const &sig_data,
      Commitment_data2 &cd2, uint8_t const *message_digest,
      uint8_t const *nonce) noexcept;
    int mpc_simulate_and_verify(randomTape_t *tapes,
      Signature_data const &sig_data, msgs_t *msgs,
      Lowmc_state_words64_ptr expected_output_ptr, shares_t *tmp_shares,
      size_t t) noexcept;
    void save_proof_data(
      Proof2 *proof, Mpc_working_data const &mpc_wd, size_t t);

    constexpr static size_t n_trees_ = Group_authpaths::n_mfors_trees_;

    constexpr static Tape_offset local_offset_bits_ =
      (n_trees_ - 1) * Lowmc_parameters::lowmc_state_bits_;

    constexpr static Tape_offset local_tape_bits_ = 0U;

    constexpr static Tape_offset aux_bits_ =
      n_trees_ * Mpc_sign_mfors::aux_bits_;

    constexpr static Mpc_param local_mpc_param_{ 0U, 0U, 0U, n_trees_ };

    constexpr static Mpc_proof_indices local_mpc_indices_delta_{ 0U, 0U, 1U };

    constexpr static Mpc_param mpc_param_ =
      scale_mpc_param(Mpc_sign_mfors::mpc_param_, n_trees_) + local_mpc_param_;

    constexpr static Mpc_proof_indices mpc_indices_delta_ =
      indices_from_mpc_param(Mpc_sign_mfors::mpc_param_)
      + local_mpc_indices_delta_;


  private:
    const Mpc_proof_indices mpc_indices_{ 0U, 0U, 0U };
    constexpr static Mpc_proof_indices mpc_indices_out_ =
      indices_from_mpc_param(local_mpc_param_);

    Group_authpaths_ptr group_paths_ptr_;

    Lowmc_state_words64 public_key_{ 0 };

    Tape_offset intermediate_root_mask_offset_[n_trees_ - 1];

    Tape_offset tree_offsets_[n_trees_];

    paramset_t paramset_;

    Tape_offset base_offset_{ 0 };
};

struct Mpc_time_point
{
    std::string type_;
    float time_;
};

using Mpc_timings = std::vector<Mpc_time_point>;

struct Mpc_timing_data
{
    F_timer_s timer_;
    Mpc_timings times_;
};

#endif
