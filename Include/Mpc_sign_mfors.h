/*******************************************************************************
 * File:        Mpc_sign_mfors.h
 * Description: Code for signing one of the MFORS tree
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



#ifndef MPC_SIGN_MFORS_H
#define MPC_SIGN_MFORS_H

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


class Mpc_sign_mfors
{
  public:
    Mpc_sign_mfors() = delete;
    Mpc_sign_mfors(Mfors_tree_paths *mpc_input_ptr,
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
      msgs_t *msgs, Lowmc_state_words64_ptr output_ptr, shares_t *tmp_shares,
      size_t t) noexcept;

    constexpr static Tape_offset offset_bits_ =
      Lowmc_parameters::lowmc_state_bits_ +// for the local root mask
      Mpc_mfors_full_paths::offset_bits_;

    constexpr static Tape_offset tape_bits_ = Mpc_mfors_full_paths::tape_bits_;

    constexpr static Tape_offset aux_bits_ = Mpc_mfors_full_paths::aux_bits_;

    constexpr static Mpc_param local_mpc_param_{ 0U, 0U, 0U, 0U };

    // ***********************************************************************

    constexpr static Mpc_param mpc_param_ =
      Mpc_mfors_full_paths::mpc_param_ + local_mpc_param_;

  private:
    Mpc_proof_indices mpc_indices_{};

    Mpc_proof_indices mpc_indices_out_{};

    bool mask_root_{ false };
    std::unique_ptr<Mpc_mfors_full_paths> mpc_mfors_paths_;

    paramset_t paramset_;

    Tape_offset base_offset_{ 0 };
};

#endif
