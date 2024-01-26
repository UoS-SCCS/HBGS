/*******************************************************************************
 * File:        Mpc_hash2.h
 * Description: Hashl function derived from Hash2
 *
 * Author:      Chris Newton
 *
 * Created:     Tuesday 19 July 2022
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



#ifndef MPC_HASH2_H
#define MPC_HASH2_H

#include "Io_utils.h"

#include <iostream>
#include <cmath>

extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}

#include "Hbgs_param.h"
#include "Lowmc64.h"
#include "Hash2_64.h"
#include "Mpc_working_data.h"
#include "Mpc_signature_utils.h"
#include "Mpc_hash1.h"
#include "Mpc_utils.h"

class Hash2
{
  public:
    Hash2() = delete;
    Hash2(Mpc_proof_indices const &indices) noexcept;
    Tape_offset set_offsets(Tape_offset const &of) noexcept;
    void compute_aux_tape_sign(randomTape_t *tapes,
      Lowmc_state_words64_const_ptr input_hash_mask,
      H2_data64 const &output_masks, Mpc_working_data &mpc_wd,
      size_t t) noexcept;
    void compute_aux_tape_verify(randomTape_t *tapes,
      H2_data64 const &output_masks,
      [[maybe_unused]] Signature_data const &sig_data, size_t t) noexcept;
    int mpc_simulate_sign(randomTape_t *tapes,
      Lowmc_state_words64_const_ptr masked_input_hash, Mpc_working_data &mpc_wd,
      shares_t *tmp_shares, size_t t) noexcept;
    void get_aux_bits(uint8_t *aux_bits, uint32_t &aux_pos,
      randomTape_t *current_tape_ptr) const noexcept;
    void set_aux_bits(randomTape_t *current_tape_ptr, uint32_t &aux_pos,
      uint8_t *aux_bits) const noexcept;
    int mpc_simulate_and_verify(randomTape_t *tapes,
      Lowmc_state_words64_const_ptr masked_input_hash,
      Signature_data const &sig_data, msgs_t *msgs, shares_t *tmp_shares,
      H2_data64 &outputs, size_t t) noexcept;

    constexpr static Tape_offset offset_bits_{ 0 };
    constexpr static Tape_offset tape_bits_ = n_hashes * Hash1a::tape_bits_;
    constexpr static Tape_offset aux_bits_ = n_hashes * Hash1a::aux_bits_;

    constexpr static Mpc_param mpc_param_{ aux_bits_, n_hashes, n_hashes,
        n_hashes };

  private:
    paramset_t paramset_;

    Tape_offset base_offset_{ null_offset };

    Lowmc_state_words64 const ctr_mask_{ 0 };// The counter is not masked

    size_t base_mpc_index_{ null_index };
    size_t base_input_index_{ null_index };
    size_t base_output_index_{ null_index };
};

#endif
