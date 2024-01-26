/*******************************************************************************
 * File:        Mpc_mfors_full_paths.h
 * Description: Code for the MFORS authpaths, starting from the initial hash
 *
 * Author:      Chris Newton
 * Created:     Saturday 23 July 2022
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



#ifndef HBGS_MFORS_FULL_PATHS_H
#define HBGS_MFORS_FULL_PATHS_H

#include <iostream>
#include <string>

#include "Clock_utils.h"
#include "Hbgs_issuer.h"
#include "Hbgs_param.h"
#include "Mpc_working_data.h"
#include "Mpc_signature_utils.h"
#include "Mpc_parameters.h"
#include "Mfors_tree.h"
#include "Mpc_mfors_authpath.h"


class Mpc_mfors_full_paths
{
  public:
    Mpc_mfors_full_paths() = delete;
    Mpc_mfors_full_paths(Mfors_tree_paths *tree_paths_ptr,
      Mpc_proof_indices const &indices) noexcept;
    Tape_offset set_offsets(Tape_offset const &of) noexcept;
    void compute_aux_tape_sign(randomTape_t *tapes,
      Lowmc_state_words64_const_ptr root_mask, Mpc_working_data &mpc_wd,
      size_t t) noexcept;
    void compute_aux_tape_verify(randomTape_t *tapes,
      Lowmc_state_words64_const_ptr root_mask,
      [[maybe_unused]] Signature_data const &sig_data, size_t t) noexcept;
    void get_aux_bits(uint8_t *aux_bits, Tape_offset &aux_pos,
      randomTape_t *tapes, size_t t) noexcept;
    void set_aux_bits(randomTape_t *tapes, Tape_offset &aux_pos,
      Signature_data const &sig_data, size_t t) noexcept;
    int mpc_simulate_sign(randomTape_t *tapes, Lowmc_state_words64_ptr output,
      Mpc_working_data &mpc_wd, shares_t *tmp_shares, size_t t) noexcept;
    int mpc_simulate_verify(randomTape_t *tapes, Signature_data const &sig_data,
      msgs_t *msgs, Lowmc_state_words64_ptr expected_output_ptr,
      shares_t *tmp_shares, size_t t) noexcept;

    // ***********************************************************************
    // These values do not depend on the number of paths_ as only a single
    // Mpc_authpath is used for each 'round' of MPC-in-the-Head
    //
    constexpr static Mt_row_type n_paths_ = Mfors_tree_paths::n_paths_;

    constexpr static Tape_offset local_offset_bits_ = 0;

    constexpr static Tape_offset authpath_offset_bits_ =
      Mpc_mfors_authpath::offset_bits_;

    constexpr static Tape_offset offset_bits_ =
      authpath_offset_bits_ + local_offset_bits_;

    constexpr static Tape_offset tape_bits_ = Mpc_mfors_authpath::tape_bits_;

    constexpr static Tape_offset aux_bits_ = Mpc_mfors_authpath::aux_bits_;

    constexpr static Mpc_param local_mpc_param_{ 0U, 0U, 0U, 0U };

    //
    // ***********************************************************************

    constexpr static Mpc_param mpc_param_ =
      Mpc_mfors_authpath::mpc_param_ + local_mpc_param_;

  private:
    Mpc_proof_indices mpc_indices_{};
    Mpc_proof_indices mfors_authpath_indices_{};
    paramset_t paramset_;

    Mfors_tree_paths *tree_paths_ptr_{ nullptr };

    Tape_offset base_offset_{ null_offset };

    Mt_tree_type current_path_no_{ Public_parameters::k_ };
    std::unique_ptr<Mpc_mfors_authpath> mpc_data_;

    void set_authpath(size_t t) noexcept;
};

#endif
