/*******************************************************************************
 * File:        Mpc_hash1.cpp
 * Description: Hash1 functions derived from Mpc_lowmc
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



#include <iostream>
#include <cmath>

extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}

#include "Hbgs_param.h"
#include "Mpc_lowmc64.h"
#include "Mpc_hash1.h"


Tape_offset Hash1a::set_offsets(Tape_offset const &of)
{
    return low_mc_.set_offsets(of);
}

void Hash1a::compute_aux_tape(randomTape_t *tapes,
  Lowmc_state_words64_const_ptr bmask,
  Lowmc_state_words64_const_ptr output_mask,
  Lowmc_state_words64_ptr mask_adjustment, paramset_t *params) const noexcept
{
    Lowmc_state_words64 lowmc_mask{ 0 };
    xor64(lowmc_mask, bmask, output_mask);

    low_mc_.compute_aux_tape(tapes, bmask, lowmc_mask, mask_adjustment, params);
}

int Hash1a::mpc_simulate(Lowmc_state_words64_const_ptr masked_input_a,
  Lowmc_state_words64_const_ptr masked_input_b, randomTape_t *tapes,
  shares_t *tmp_shares, msgs_t *msgs, Lowmc_state_words64_ptr output,
  paramset_t *params) const noexcept
{
    int rv = low_mc_.mpc_simulate(
      masked_input_a, masked_input_b, tapes, tmp_shares, msgs, output, params);
    if (rv != EXIT_SUCCESS) {
        std::cerr << "mpc_simulate for hash1a failed\n";
        return EXIT_FAILURE;
    }
    xor64(output, masked_input_b);

    return EXIT_SUCCESS;
}

void Hash1a::get_aux_bits(
  uint8_t *output, uint32_t &pos, randomTape_t *tapes) const noexcept
{
    low_mc_.get_aux_bits(output, pos, tapes);
}
void Hash1a::set_aux_bits(
  randomTape_t *tapes, uint32_t &pos, uint8_t *input) const noexcept
{
    low_mc_.set_aux_bits(tapes, pos, input);
}

Tape_offset Hash1b::set_offsets(Tape_offset const &of) noexcept
{
    Tape_offset next_offset = of;

    intermediate_mask_offset_ = next_offset;
    next_offset += Mpc_parameters::lowmc_state_bits_;

    next_offset = hash1a_1_.set_offsets(next_offset);

    next_offset = hash1a_2_.set_offsets(next_offset);

    assertm(next_offset - of == offset_bits_ + tape_bits_,
      "Hash1b: inconsistent offsets");

    return next_offset;
}

void Hash1b::compute_aux_tape(randomTape_t *current_tape_ptr,
  Lowmc_state_words64_const_ptr a_mask, Lowmc_state_words64_const_ptr b_mask,
  Lowmc_state_words64_const_ptr c_mask, Lowmc_state_words64_const_ptr hash_mask,
  Lowmc_state_words64_ptr adjusted_a_mask,
  Lowmc_state_words64_ptr adjusted_intermediate_mask, paramset_t *params) const
  noexcept
{
    Lowmc_state_words64 intermediate_mask = { 0 };
    get_mask_from_tapes(
      intermediate_mask, current_tape_ptr, intermediate_mask_offset_, params);

    hash1a_1_.compute_aux_tape(
      current_tape_ptr, b_mask, intermediate_mask, adjusted_a_mask, params);

    hash1a_2_.compute_aux_tape(
      current_tape_ptr, c_mask, hash_mask, adjusted_intermediate_mask, params);


    // Use the hash1a output (adjusted_a_mask) to adjust the a_mask and save for
    // later
    Word *tmp{ nullptr };
    if (adjusted_a_mask != nullptr) {
        tmp = adjusted_a_mask;
        xor64(tmp, a_mask);
    }
    // Use the hash1a output (adjusted_intermediate_mask) to adjust the
    // intermediate mask and and save for later
    if (adjusted_intermediate_mask != nullptr) {
        tmp = adjusted_intermediate_mask;
        xor64(tmp, intermediate_mask);
    }
}

int Hash1b::mpc_simulate(Lowmc_state_words64_const_ptr remasked_input_a,
  Lowmc_state_words64_const_ptr masked_input_b,
  Lowmc_state_words64_const_ptr masked_input_c,
  Lowmc_state_words64_const_ptr adjusted_intermediate_mask,
  randomTape_t *current_tape_ptr, shares_t *tmp_shares, msgs_t *msgs,
  Lowmc_state_words64_ptr hash_output, paramset_t *params) const noexcept
{
    Lowmc_state_words64 intermediate_state{ 0 };
    int rv = hash1a_1_.mpc_simulate(remasked_input_a,
      masked_input_b,
      current_tape_ptr,
      tmp_shares,
      msgs,
      intermediate_state,
      params);
    if (rv != EXIT_SUCCESS) {
        std::cerr << "Hash1b::mpc_simulate: initial hash failed\n";
        return EXIT_FAILURE;
    }

    // Re-mask the first input (of the second hash) and save the state for
    // verify
    Lowmc_state_words64 remasked_first_input{ 0 };
    xor64(remasked_first_input, adjusted_intermediate_mask, intermediate_state);

    rv = hash1a_2_.mpc_simulate(remasked_first_input,
      masked_input_c,
      current_tape_ptr,
      tmp_shares,
      msgs,
      hash_output,
      params);

    return rv;
}

void Hash1b::get_aux_bits(
  uint8_t *aux_bits, uint32_t &pos, randomTape_t *tapes) const noexcept
{
    hash1a_1_.get_aux_bits(aux_bits, pos, tapes);
    hash1a_2_.get_aux_bits(aux_bits, pos, tapes);
}
void Hash1b::set_aux_bits(
  randomTape_t *tapes, uint32_t &pos, uint8_t *aux_bits) const noexcept
{
    hash1a_1_.set_aux_bits(tapes, pos, aux_bits);
    hash1a_2_.set_aux_bits(tapes, pos, aux_bits);
}
