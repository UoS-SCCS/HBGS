/*******************************************************************************
 * File:        Mpc_hash1.h
 * Description: Hash1 functions derived from Hash1a
 *
 * Author:      Chris Newton
 *
 * Created:     Monday 7 March 2022
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



#ifndef MPC_HASH1_H
#define MPC_HASH1_H

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
#include "Mpc_lowmc64.h"
#include "Mpc_utils.h"

void hash1a(Lowmc_state_words64_ptr hash, Lowmc_state_words64_const_ptr a,
  Lowmc_state_words64_const_ptr b, paramset_t *params) noexcept;

class Hash1a
{
  public:
    Hash1a() = default;
    Tape_offset set_offsets(Tape_offset const &of);
    void compute_aux_tape(randomTape_t *tapes,
      Lowmc_state_words64_const_ptr bmask,
      Lowmc_state_words64_const_ptr output_mask,
      Lowmc_state_words64_ptr a_mask_adjustment,
      paramset_t *params) const noexcept;
    int mpc_simulate(Lowmc_state_words64_const_ptr masked_a_input,
      Lowmc_state_words64_const_ptr masked_b_input, randomTape_t *tapes,
      shares_t *tmp_shares, msgs_t *msgs, Lowmc_state_words64 output,
      paramset_t *params) const noexcept;
    void get_aux_bits(
      uint8_t *aux_bits, uint32_t &pos, randomTape_t *tapes) const noexcept;
    void set_aux_bits(
      randomTape_t *tapes, uint32_t &pos, uint8_t *aux_bits) const noexcept;

    constexpr static Tape_offset offset_bits_{ 0 };
    constexpr static Tape_offset tape_bits_ = Mpc_lowmc64::tape_bits_;
    constexpr static Tape_offset aux_bits_ = Mpc_lowmc64::aux_bits_;

  private:
    Mpc_lowmc64 low_mc_{};
};

void hash1b(Lowmc_state_words64_ptr hash, Lowmc_state_words64_const_ptr a,
  Lowmc_state_words64_const_ptr b, Lowmc_state_words64_const_ptr c,
  paramset_t *params) noexcept;

class Hash1b
{
  public:
    Hash1b() = default;
    Tape_offset set_offsets(Tape_offset const &of) noexcept;
    void compute_aux_tape(randomTape_t *tapes,
      Lowmc_state_words64_const_ptr a_mask,
      Lowmc_state_words64_const_ptr b_mask,
      Lowmc_state_words64_const_ptr c_mask,
      Lowmc_state_words64_const_ptr hash_mask,
      Lowmc_state_words64_ptr adjusted_a_mask,
      Lowmc_state_words64_ptr adjusted_intermediate_mask,
      paramset_t *params) const noexcept;
    int mpc_simulate(Lowmc_state_words64_const_ptr remasked_input_a,
      Lowmc_state_words64_const_ptr masked_input_b,
      Lowmc_state_words64_const_ptr masked_input_c,
      Lowmc_state_words64_const_ptr adjusted_intermediate_mask,
      randomTape_t *tapes, shares_t *tmp_shares, msgs_t *msgs,
      Lowmc_state_words64_ptr hash_output, paramset_t *params) const noexcept;
    void get_aux_bits(uint8_t *output, uint32_t &pos, randomTape_t *tapes) const
      noexcept;
    void set_aux_bits(randomTape_t *tapes, uint32_t &pos, uint8_t *input) const
      noexcept;

    constexpr static Tape_offset local_offset_bits_ =
      Mpc_parameters::lowmc_state_bits_;// For the intermediate mask
    constexpr static Tape_offset offset_bits_ =
      2 * Hash1a::offset_bits_ + local_offset_bits_;
    constexpr static Tape_offset tape_bits_ = 2 * Hash1a::tape_bits_;
    constexpr static Tape_offset aux_bits_ = 2 * Hash1a::aux_bits_;

  private:
    Tape_offset intermediate_mask_offset_{ null_offset };

    Hash1a hash1a_1_;
    Hash1a hash1a_2_;
};

#endif
