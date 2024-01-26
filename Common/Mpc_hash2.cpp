/*******************************************************************************
 * File:        Mpc_hash2.h
 * Description: Hashl function derived from Hash1a
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



#include <iostream>
#include <cmath>

extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}

#include "Hbgs_param.h"
#include "Lowmc64.h"
#include "Mpc_hash2.h"

#define DEBUG_MPC_HASH2

Hash2::Hash2(Mpc_proof_indices const &indices) noexcept
{
    base_input_index_ = indices.input_index_;
    base_mpc_index_ = indices.mpc_input_index_;
    base_output_index_ = indices.output_index_;

    get_param_set(get_picnic_parameter_set_id(), &paramset_);
}

Tape_offset Hash2::set_offsets(Tape_offset const &of) noexcept
{
    base_offset_ = of;

    return base_offset_ + tape_bits_;
}

void Hash2::compute_aux_tape_sign(randomTape_t *tapes,
  Lowmc_state_words64_const_ptr input_hash_mask, H2_data64 const &output_masks,
  Mpc_working_data &mpc_wd, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

#ifdef DEBUG_MPC_HASH2
    if (t == 0) {
        std::cout << "\nHash2::compute_aux_tape_sign\nInput hash mask:\n";
        print_lowmc_state_bytes(std::cout, (uint8_t *)input_hash_mask);
        std::cout << "\nhash2 output masks:\n";
        print_h2_data(std::cout, output_masks);
        std::cout << '\n';
    }
#endif

    Tape_offset next_offset{ base_offset_ };
    for (uint32_t i = 0; i < n_hashes; ++i) {

        Lowmc_state_words64_ptr mask_adjustment =
          (Word *)mpc_wd.mpc_inputs_[base_mpc_index_ + i][t];

        Hash1a hash1a{};
        next_offset = hash1a.set_offsets(next_offset);

        hash1a.compute_aux_tape(current_tape_ptr, ctr_mask_, output_masks[i],
          mask_adjustment, &paramset_);

        xor64(mask_adjustment, input_hash_mask);
    }
}

void Hash2::compute_aux_tape_verify(randomTape_t *tapes,
  H2_data64 const &output_masks,
  [[maybe_unused]] Signature_data const &sig_data, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

#ifdef DEBUG_MPC_HASH2
    if (t == 0) {
        std::cout << "\nHash2::compute_aux_tape_verify\noutput masks:\n";
        print_h2_data(std::cout, output_masks);
        std::cout << '\n';
    }
#endif

    Tape_offset next_offset{ base_offset_ };
    for (uint32_t i = 0; i < n_hashes; ++i) {
        Hash1a hash1a{};
        next_offset = hash1a.set_offsets(next_offset);

        hash1a.compute_aux_tape(
          current_tape_ptr, ctr_mask_, output_masks[i], nullptr, &paramset_);
    }
}

void Hash2::get_aux_bits(uint8_t *aux_bits, uint32_t &aux_pos,
  randomTape_t *current_tape_ptr) const noexcept
{
    Tape_offset next_offset{ base_offset_ };
    for (uint32_t i = 0; i < n_hashes; ++i) {
        Hash1a hash1a{};
        next_offset = hash1a.set_offsets(next_offset);

        hash1a.get_aux_bits(aux_bits, aux_pos, current_tape_ptr);
    }
}

void Hash2::set_aux_bits(randomTape_t *current_tape_ptr, uint32_t &aux_pos,
  uint8_t *aux_bits) const noexcept
{
    Tape_offset next_offset{ base_offset_ };
    for (uint32_t i = 0; i < n_hashes; ++i) {
        Hash1a hash1a{};
        next_offset = hash1a.set_offsets(next_offset);

        hash1a.set_aux_bits(current_tape_ptr, aux_pos, aux_bits);
    }
}

int Hash2::mpc_simulate_sign(randomTape_t *tapes,
  Lowmc_state_words64_const_ptr masked_input_hash, Mpc_working_data &mpc_wd,
  shares_t *tmp_shares, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

    int rv = 0;
    Tape_offset next_offset{ base_offset_ };
    Lowmc_state_words64 remasked_input{ 0 };
    for (uint32_t i = 0; i < n_hashes; ++i) {
        Lowmc_state_words64_ptr mask_adjustment =
          (Word *)mpc_wd.mpc_inputs_[base_mpc_index_ + i][t];

        xor64(remasked_input, mask_adjustment, masked_input_hash);

        Lowmc_state_words64 ctr{ 0 };
        set_hash2_counter(ctr, i);

        Hash1a hash1a{};
        next_offset = hash1a.set_offsets(next_offset);
        rv = hash1a.mpc_simulate(remasked_input,
          ctr,
          current_tape_ptr,
          tmp_shares,
          &mpc_wd.msgs_[t],
          (Word *)mpc_wd.outputs_[base_output_index_ + i][t],
          &paramset_);
        if (rv != 0) {
            std::cerr << "Hash2: mpc_simulate_sign failed for t=" << t
                      << " and i=" << i << '\n';
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int Hash2::mpc_simulate_and_verify(randomTape_t *tapes,
  Lowmc_state_words64_const_ptr masked_input_hash,
  Signature_data const &sig_data, msgs_t *msgs, shares_t *tmp_shares,
  H2_data64 &outputs, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

    int rv = 0;
    Tape_offset next_offset{ base_offset_ };
    Lowmc_state_words64 remasked_input{ 0 };
    for (uint32_t i = 0; i < n_hashes; ++i) {
        Lowmc_state_words64_ptr mask_adjustment =
          (Word *)sig_data.proofs_[t]->mpc_inputs_[base_mpc_index_ + i];

        xor64(remasked_input, mask_adjustment, masked_input_hash);

        Lowmc_state_words64 ctr{ 0 };
        set_hash2_counter(ctr, i);

        Hash1a hash1a{};
        next_offset = hash1a.set_offsets(next_offset);
        rv = hash1a.mpc_simulate(remasked_input,
          ctr,
          current_tape_ptr,
          tmp_shares,
          msgs,
          outputs[i],
          &paramset_);
        if (rv != 0) {
            std::cerr << "Hash2: mpc_simulate_and_verify failed for t=" << t
                      << " and i=" << i << '\n';
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
