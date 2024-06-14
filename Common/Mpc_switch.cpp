/*******************************************************************************
 * File:        Mpc_switch.cpp
 * Description: Code for MPC Switch, used when traversing the tree with
 * 				      masked index
 *
 * Author:      Chris Newton
 *
 * Created:     Tuesday 15 March 2022
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



#include "Io_utils.h"

#include <iostream>
#include <cstring>
#include <cmath>

#include "Picnic_mpc_functions.h"
#include "Mpc_parameters.h"
#include "Mpc_utils.h"
#include "Mpc_lowmc64.h"
#include "Mpc_switch.h"

Tape_offset Mpc_switch::set_offsets(Tape_offset const &of) noexcept
{
    mpc_and_tape_offset_ = of;
    return of + tape_bits_;
}

void Mpc_switch::compute_aux_tape(randomTape_t *current_tape_ptr,
  Lowmc_state_words64_const_ptr bit_mask, Lowmc_state_words64_const_ptr ca_mask,
  Lowmc_state_words64_const_ptr w_mask, paramset_t *params) const noexcept
{
    current_tape_ptr->pos = mpc_and_tape_offset_;
    for (uint32_t i = 0; i < Lowmc_parameters::lowmc_state_bits_; ++i) {

        uint8_t cab = get_bit_from_word_array64(ca_mask, i);
        uint8_t eb = get_bit_from_word_array64(bit_mask, i);
        uint8_t wb = get_bit_from_word_array64(w_mask, i);

        aux_mpc_AND(cab, eb, wb, current_tape_ptr, params);
    }
}

int Mpc_switch::mpc_simulate(Lowmc_state_words64_const_ptr extended_masked_b,
  Lowmc_state_words64_const_ptr masked_c,
  Lowmc_state_words64_const_ptr masked_a, randomTape_t *current_tape_ptr,
  Tape_offset bit_mask_offset, Tape_offset c_mask_offset,
  Tape_offset a_mask_offset, msgs_t *msgs, Lowmc_state_words64_ptr output,
  paramset_t *params) const noexcept
{
    Lowmc_state_words64 masked_ca{ 0 };
    xor64(masked_ca, masked_c, masked_a);

    uint16_t b_shares[Lowmc_parameters::lowmc_state_bits_]{ 0 };
    if (bit_mask_offset != null_offset) {
        current_tape_ptr->pos = bit_mask_offset;
        for (uint32_t i = 0; i < Lowmc_parameters::lowmc_state_bits_; ++i) {
            b_shares[i] = tapesToWord(current_tape_ptr);
        }
    }

    uint16_t c_shares[Lowmc_parameters::lowmc_state_bits_]{ 0 };
    if (c_mask_offset != null_offset) {
        current_tape_ptr->pos = c_mask_offset;
        for (uint32_t i = 0; i < Lowmc_parameters::lowmc_state_bits_; ++i) {
            c_shares[i] = tapesToWord(current_tape_ptr);
        }
    }

    uint16_t a_shares[Lowmc_parameters::lowmc_state_bits_]{ 0 };
    if (a_mask_offset != null_offset) {
        current_tape_ptr->pos = a_mask_offset;
        for (uint32_t i = 0; i < Lowmc_parameters::lowmc_state_bits_; ++i) {
            a_shares[i] = tapesToWord(current_tape_ptr);
        }
    }

    current_tape_ptr->pos = mpc_and_tape_offset_;
    Lowmc_state_words64 w{ 0 };

    for (uint32_t i = 0; i < Lowmc_parameters::lowmc_state_bits_; ++i) {
        uint8_t cab = get_bit_from_word_array64(masked_ca, i);
        uint8_t eb = get_bit_from_word_array64(extended_masked_b, i);

        uint8_t wb = mpc_AND(cab, eb, c_shares[i] ^ a_shares[i], b_shares[i],
          current_tape_ptr, msgs, params);

        set_bit_in_word_array64(w, i, wb);
    }

    if (output != nullptr) {
        memcpy(output, (uint8_t *)w, params->stateSizeBytes);
    }
    return 0;
}

void Mpc_switch::get_aux_bits(
  uint8_t *output, uint32_t &pos, randomTape_t *current_tape_ptr) const noexcept
{
    constexpr uint32_t last = Mpc_parameters::mpc_parties_ - 1U;
    constexpr uint32_t n = Lowmc_parameters::lowmc_state_bits_;

    uint32_t start_of_aux_bits = mpc_and_tape_offset_;

    for (uint32_t i = 0; i < n; i++) {
        setBit(output, pos++,
          getBit(current_tape_ptr->tape[last], start_of_aux_bits + i));
    }
}

void Mpc_switch::set_aux_bits(
  randomTape_t *current_tape_ptr, uint32_t &pos, uint8_t *input) const noexcept
{
    constexpr uint32_t last = Mpc_parameters::mpc_parties_ - 1U;
    constexpr uint32_t n = Lowmc_parameters::lowmc_state_bits_;

    uint32_t start_of_aux_bits = mpc_and_tape_offset_;

    for (uint32_t i = 0; i < n; i++) {
        setBit(current_tape_ptr->tape[last], start_of_aux_bits + i,
          getBit(input, pos++));
    }
}
