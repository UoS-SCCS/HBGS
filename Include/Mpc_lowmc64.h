/*******************************************************************************
 * File:        Mpc_lowmc64.h
 * Description: Utilities used for MPC
 *
 * Author:      Chris Newton
 *
 * Created:     Friday 28 January 2022
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



#ifndef MPC_LOWMC64_H
#define MPC_LOWMC64_H

#include <iostream>
#include <fstream>
#include <cmath>

extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}

#include "Lowmc64.h"
#include "Lowmc32.h"
#include "Hbgs_param.h"
#include "Mpc_parameters.h"
#include "Mpc_utils.h"

class Mpc_lowmc64
{
  public:
    Mpc_lowmc64() = default;
    Tape_offset set_offsets(Tape_offset const &of) noexcept;
    void compute_aux_tape(randomTape_t *current_tape_ptr,
      Lowmc_state_words64_const_ptr pmask,
      Lowmc_state_words64_const_ptr lowmc_mask,
      Lowmc_state_words64_ptr key_mask_adjustment, paramset_t *params) const
      noexcept;
    int mpc_simulate(Lowmc_state_words64_const_ptr masked_key_input,
      Lowmc_state_words64_const_ptr masked_plaintext,
      randomTape_t *current_tape_ptr, shares_t *tmp_shares, msgs_t *msgs,
      Lowmc_state_words64 masked_output, paramset_t *params) const noexcept;
    void get_aux_bits(uint8_t *aux_bits, uint32_t &pos,
      randomTape_t *current_tape_ptr) const noexcept;
    void set_aux_bits(randomTape_t *current_tape_ptr, uint32_t &pos,
      uint8_t *aux_bits) const noexcept;
    constexpr static Tape_offset offset_bits_ = { 0 };
    constexpr static Tape_offset aux_bits_ = Lowmc_parameters::lowmc_ands_bits_;
    // Two sets of bits needed for each round
    constexpr static Tape_offset tape_bits_ =
      2 * Lowmc_parameters::lowmc_ands_bits_;

  private:
    Tape_offset offset_{ null_offset };
};

void aux_mpc_sbox64(Lowmc_state_words64 const &in,
  Lowmc_state_words64 const &out,
  randomTape_t *tapes,
  paramset_t *params);

uint8_t get_bit_from_word_array64(
  Lowmc_state_words64_const_ptr array, uint32_t bit_number);

void set_bit_in_word_array64(
  Lowmc_state_words64_ptr array, uint32_t bit_number, uint8_t value);

#endif
