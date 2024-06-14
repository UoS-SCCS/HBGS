/*******************************************************************************
 * File:        Mpc_lowmc64.cpp
 * Description: Structures and utilities used for MPC using uint64_t
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



#include "Io_utils.h"

#include <iostream>
#include <fstream>
#include <cstring>
#include <cmath>

#include "Picnic_mpc_functions.h"
#include "Mpc_utils.h"
#include "Mpc_lowmc64.h"

Tape_offset Mpc_lowmc64::set_offsets(Tape_offset const &of) noexcept
{
    offset_ = of;
    return of + tape_bits_;
}

void Mpc_lowmc64::compute_aux_tape(randomTape_t *current_tape_ptr,
  Lowmc_state_words64_const_ptr pmask, Lowmc_state_words64_const_ptr lowmc_mask,
  Lowmc_state_words64_ptr mask_adjustment, paramset_t *params) const noexcept
{
    Lowmc_state_words64 round_key = { 0 };
    Lowmc_state_words64 x = { 0 };
    Lowmc_state_words64 y;
    Lowmc_state_words64 key;
    Lowmc_state_words64 key0;
    Lowmc_state_words64 key0pm;

    uint32_t tape_offset = offset_;

    get_mask_from_tapes(key0, current_tape_ptr, tape_offset, params);
    // key = (key0 xor pmask) x KMatrix[0]^(-1)
    xor64(key0pm, key0, pmask);
    matrix_mul64(key, key0pm, Lowmc_matrices::kmi_[0]);
    if (mask_adjustment != NULL) {
        std::memcpy(mask_adjustment, key, params->stateSizeBytes);
    }
    // Now work back from the output mask
    std::memcpy(x, lowmc_mask, params->stateSizeBytes);
    for (uint32_t r = params->numRounds; r > 0; r--) {
        matrix_mul64(round_key, key,
          Lowmc_matrices::km_[r]);// round_key = key * KMatrix(r)
        xor64(x, round_key);
        matrix_mul64(y, x, Lowmc_matrices::lmi_[r - 1]);

        if (r == 1) {
            // Use key as input
            tape_offset = offset_;
            std::memcpy(x, key0, params->stateSizeBytes);
        } else {
            tape_offset = offset_ + params->stateSizeBits * 2 * (r - 1);
            get_mask_from_tapes(x, current_tape_ptr, tape_offset, params);
        }

        current_tape_ptr->pos = tape_offset + params->stateSizeBits;
        aux_mpc_sbox64(x, y, current_tape_ptr, params);
    }
}

int Mpc_lowmc64::mpc_simulate(Lowmc_state_words64_const_ptr masked_input,
  Lowmc_state_words64_const_ptr masked_plaintext,
  randomTape_t *current_tape_ptr, shares_t *tmp_shares, msgs_t *msgs,
  Lowmc_state_words64_ptr output, paramset_t *params) const noexcept
{
    int ret = 0;
    Lowmc_state_words64 round_key = { 0 };
    Lowmc_state_words64 state = { 0 };

    uint32_t initial_tape_offset = offset_;// Initial offset for simulation

    std::memcpy(state, masked_plaintext, params->stateSizeBytes);
    matrix_mul64(round_key, masked_input,
      Lowmc_matrices::km_[0]);// round_key = maskedKey * KMatrix[0]

    xor64(state, round_key);
    current_tape_ptr->pos = initial_tape_offset;
    for (uint32_t r = 1; r <= params->numRounds; r++) {
        tapesToWords(tmp_shares, current_tape_ptr);
        mpc_sbox((uint32_t *)state, tmp_shares, current_tape_ptr, msgs, params);
        matrix_mul64(state, state,
          Lowmc_matrices::lm_[r - 1]);// state = state * LMatrix (r-1)
        xor64(state, Lowmc_matrices::rc_[r - 1]);
        matrix_mul64(round_key, masked_input, Lowmc_matrices::km_[r]);
        xor64(state, round_key);
    }
    // Output the ciphertext
    if (output != NULL) {// We are signing and want to save the output
        std::memcpy(output, (uint8_t *)state, params->stateSizeBytes);
    }

    return ret;
}

void Mpc_lowmc64::get_aux_bits(
  uint8_t *output, uint32_t &pos, randomTape_t *current_tape_ptr) const noexcept
{
    constexpr uint32_t last = Mpc_parameters::mpc_parties_ - 1U;
    constexpr uint32_t n = Lowmc_parameters::lowmc_state_bits_;

    uint32_t start_of_aux_bits = offset_ + n;

    for (uint32_t j = 0; j < Lowmc_parameters::lowmc_rounds_; j++) {
        for (uint32_t i = 0; i < n; i++) {
            setBit(output, pos++,
              getBit(current_tape_ptr->tape[last], start_of_aux_bits + i));
        }
        start_of_aux_bits += 2 * n;
    }
}

void Mpc_lowmc64::set_aux_bits(
  randomTape_t *current_tape_ptr, uint32_t &pos, uint8_t *input) const noexcept
{
    constexpr uint32_t last = Mpc_parameters::mpc_parties_ - 1U;
    constexpr uint32_t n = Lowmc_parameters::lowmc_state_bits_;

    uint32_t start_of_aux_bits = offset_ + n;

    for (uint32_t j = 0; j < Lowmc_parameters::lowmc_rounds_; j++) {
        for (uint32_t i = 0; i < n; i++) {
            setBit(current_tape_ptr->tape[last], start_of_aux_bits + i,
              getBit(input, pos++));
        }
        start_of_aux_bits += 2 * n;
    }
}

void aux_mpc_sbox64(Lowmc_state_words64 const &in,
  Lowmc_state_words64 const &out,
  randomTape_t *tapes,
  paramset_t *params)
{
    aux_mpc_sbox((const uint32_t *)in, (const uint32_t *)out, tapes,
      params);//!!!! Replace this later
}

uint8_t get_bit_from_word_array64(
  Lowmc_state_words64_const_ptr array, uint32_t bit_number)
{
    return getBitFromWordArray((uint32_t *)array, bit_number);
    //!!!! Possibly replace this later
}

void set_bit_in_word_array64(
  Lowmc_state_words64_ptr array, uint32_t bit_number, uint8_t value)
{
    setBitInWordArray((uint32_t *)array, bit_number, value);
    //!!!! Possibly replace this later
}
