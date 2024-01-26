/*******************************************************************************
 * File:        Mpc_lowmc.cpp
 * Description: Structures and utilities used for MPC
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
#include "Mpc_lowmc.h"
#include "Mpc_utils.h"

//#define DEBUG_LOWMC_IO


Tape_offset LowMC::set_offsets(Tape_offset const &of) noexcept
{
    offset_ = of;
    return of + tape_bits_;
}

void LowMC::compute_aux_tape(randomTape_t *current_tape_ptr,
  Lowmc_state_words_const_ptr pmask, Lowmc_state_words_const_ptr lowmc_mask,
  Lowmc_state_words_ptr mask_adjustment, paramset_t *params) const noexcept
{
    Lowmc_state_words roundKey = { 0 };
    Lowmc_state_words x = { 0 };
    Lowmc_state_words y;
    Lowmc_state_words key;
    Lowmc_state_words key0;
    Lowmc_state_words key0pm;

    uint32_t tape_offset = offset_;

    get_mask_from_tapes(key0, current_tape_ptr, tape_offset, params);
    // key = (key0 xor pmask) x KMatrix[0]^(-1)
    xor_array(key0pm, key0, pmask, params->stateSizeWords);
    matrix_mul(key, key0pm, KMatrixInv(0, params), params);
    if (mask_adjustment != NULL) {
        std::memcpy(mask_adjustment, key, params->stateSizeBytes);
    }
    // Now work back from the output mask
    memcpy(x, lowmc_mask, params->stateSizeBytes);
    for (uint32_t r = params->numRounds; r > 0; r--) {
        matrix_mul(roundKey,
          key,
          KMatrix(r, params),
          params);// roundKey = key * KMatrix(r)
        xor_array(x, x, roundKey, params->stateSizeWords);
        matrix_mul(y, x, LMatrixInv(r - 1, params), params);

        if (r == 1) {
            // Use key as input
            tape_offset = offset_;
            memcpy(x, key0, params->stateSizeBytes);
        } else {
            tape_offset = offset_ + params->stateSizeBits * 2 * (r - 1);
            get_mask_from_tapes(x, current_tape_ptr, tape_offset, params);
        }

        current_tape_ptr->pos = tape_offset + params->stateSizeBits;
        aux_mpc_sbox(x, y, current_tape_ptr, params);
    }
}

int LowMC::mpc_simulate(Lowmc_state_words_const_ptr masked_input,
  Lowmc_state_words_const_ptr masked_plaintext, randomTape_t *current_tape_ptr,
  shares_t *tmp_shares, msgs_t *msgs, Lowmc_state_words_ptr output,
  paramset_t *params) const noexcept
{
    int ret = 0;
    Lowmc_state_words roundKey = { 0 };
    Lowmc_state_words state = { 0 };

    uint32_t initial_tape_offset = offset_;// Initial offset for simulation

    memcpy(state, masked_plaintext, params->stateSizeBytes);
    matrix_mul(roundKey,
      masked_input,
      KMatrix(0, params),
      params);// roundKey = maskedKey * KMatrix[0]

    xor_array(state,
      roundKey,
      state,
      params->stateSizeWords);// state = plaintext + roundKey
    current_tape_ptr->pos = initial_tape_offset;
    for (uint32_t r = 1; r <= params->numRounds; r++) {
        tapesToWords(tmp_shares, current_tape_ptr);
        mpc_sbox(state, tmp_shares, current_tape_ptr, msgs, params);
        matrix_mul(state,
          state,
          LMatrix(r - 1, params),
          params);// state = state * LMatrix (r-1)
        xor_array(state,
          state,
          RConstant(r - 1, params),
          params->stateSizeWords);// state += RConstant
        matrix_mul(roundKey, masked_input, KMatrix(r, params), params);
        xor_array(state,
          roundKey,
          state,
          params->stateSizeWords);// state += roundKey
    }
    // Output the ciphertext
    if (output != NULL) {// We are signing and want to save the output
        memcpy(output, (uint8_t *)state, params->stateSizeBytes);
    }

    return ret;
}

void LowMC::get_aux_bits(
  uint8_t *output, uint32_t &pos, randomTape_t *current_tape_ptr) const noexcept
{
    constexpr uint32_t last = Mpc_parameters::mpc_parties_ - 1U;
    constexpr uint32_t n = Mpc_parameters::lowmc_state_bits_;

    uint32_t start_of_aux_bits = offset_ + n;

    for (uint32_t j = 0; j < Mpc_parameters::lowmc_rounds_; j++) {
        for (uint32_t i = 0; i < n; i++) {
            setBit(output, pos++,
              getBit(current_tape_ptr->tape[last], start_of_aux_bits + i));
        }
        start_of_aux_bits += 2 * n;
    }
}

void LowMC::set_aux_bits(
  randomTape_t *current_tape_ptr, uint32_t &pos, uint8_t *input) const noexcept
{
    constexpr uint32_t last = Mpc_parameters::mpc_parties_ - 1U;
    constexpr uint32_t n = Mpc_parameters::lowmc_state_bits_;

    uint32_t start_of_aux_bits = offset_ + n;

    for (uint32_t j = 0; j < Mpc_parameters::lowmc_rounds_; j++) {
        for (uint32_t i = 0; i < n; i++) {
            setBit(current_tape_ptr->tape[last], start_of_aux_bits + i,
              getBit(input, pos++));
        }
        start_of_aux_bits += 2 * n;
    }
}
