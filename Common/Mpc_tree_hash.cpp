/*******************************************************************************
 * File:        Mpc_tree_hash.cpp
 * Description: Code for the  different Merkle tree hashes
 *
 * Author:      Chris Newton
 * Created:     Sunday 17 April 2022
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


#include <cmath>
#include <cinttypes>
#include <cstring>
#include <thread>
#include <exception>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include "Io_utils.h"

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
}

#include "Hbgs_param.h"
#include "Picnic_mpc_functions.h"
#include "Mpc_utils.h"
#include "Mpc_lowmc64.h"
#include "Mpc_parameters.h"
#include "Mpc_signature_utils.h"
#include "Mpc_working_data.h"
#include "Mpc_sign.h"
#include "Mpc_verify.h"
#include "Mpc_node_address.h"
#include "Mpc_switch.h"
#include "Mpc_tree_hash.h"

Tape_offset Masked_tree_hash::set_offsets(Tape_offset of) noexcept
{
    Tape_offset next_offset = of;

    bit_mask_offset_ = next_offset;
    next_offset += Mpc_parameters::lowmc_state_bits_;

    // Mask for output from mpc_switch
    intermediate_mask_offset_ = next_offset;
    next_offset += Mpc_parameters::lowmc_state_bits_;

    next_offset = mpc_switch_.set_offsets(next_offset);

    next_offset = hash1b_.set_offsets(next_offset);

    assertm(next_offset - of == offset_bits_ + tape_bits_,
      "Masked_tree_hash: inconsistent offsets");

    return next_offset;
}

void Masked_tree_hash::compute_aux_tape(randomTape_t *current_tape_ptr,
  Lowmc_state_words64_const_ptr c_mask, Lowmc_state_words64_const_ptr a_mask,
  Lowmc_state_words64_const_ptr node_mask,
  Lowmc_state_words64_const_ptr hash_mask,
  Lowmc_state_words64_ptr adjusted_first_mask,
  Lowmc_state_words64_ptr adjusted_intermediate_mask,
  paramset_t *params) noexcept
{
    Lowmc_state_words64 bit_mask{ 0 };
    if (bit_mask_offset_ != null_offset) {
        get_mask_from_tapes(
          bit_mask, current_tape_ptr, bit_mask_offset_, params);
    }

    Lowmc_state_words64 i_mask{ 0 };
    get_mask_from_tapes(
      i_mask, current_tape_ptr, intermediate_mask_offset_, params);

    Lowmc_state_words64 ca_mask{ 0 };
    xor64(ca_mask, c_mask, a_mask);

    mpc_switch_.compute_aux_tape(
      current_tape_ptr, bit_mask, ca_mask, i_mask, params);

    Lowmc_state_words64 left_mask{ 0 };
    xor64(left_mask, i_mask, c_mask);
    Lowmc_state_words64 right_mask{ 0 };
    xor64(right_mask, i_mask, a_mask);

    hash1b_.compute_aux_tape(current_tape_ptr, left_mask, right_mask, node_mask,
      hash_mask, adjusted_first_mask, adjusted_intermediate_mask, params);
}

void Masked_tree_hash::get_aux_bits(
  uint8_t *aux_bits, uint32_t &aux_pos, randomTape_t *current_tape_ptr) noexcept
{
    mpc_switch_.get_aux_bits(aux_bits, aux_pos, current_tape_ptr);
    hash1b_.get_aux_bits(aux_bits, aux_pos, current_tape_ptr);
}

void Masked_tree_hash::set_aux_bits(
  randomTape_t *current_tape_ptr, uint32_t &aux_pos, uint8_t *aux_bits) noexcept
{
    mpc_switch_.set_aux_bits(current_tape_ptr, aux_pos, aux_bits);
    hash1b_.set_aux_bits(current_tape_ptr, aux_pos, aux_bits);
}

int Masked_tree_hash::mpc_simulate_sign(randomTape_t *current_tape_ptr,
  Lowmc_state_words64_const_ptr masked_current,
  Lowmc_state_words64_const_ptr masked_auth,
  Lowmc_state_words64_const_ptr masked_node, Tape_offset cmask_offset,
  Tape_offset amask_offset, uint8_t bit_value,
  [[maybe_unused]] shares_t *tmp_shares, msgs_t *msgs,
  Lowmc_state_words64_ptr extended_masked_b,
  Lowmc_state_words64_const_ptr first_input_mask_adjustment,
  Lowmc_state_words64_const_ptr intermediate_mask_adjustment,
  Lowmc_state_words64_ptr masked_hash, paramset_t *params) noexcept
{
    Lowmc_state_words64 bit_mask = { 0 };
    if (bit_mask_offset_ != null_offset) {
        get_mask_from_tapes(
          bit_mask, current_tape_ptr, bit_mask_offset_, params);
    }

    uint64_t b_base_value = ((bit_value)&1) ? 0xffffffffffffffff : 0;
    for (size_t i = 0; i < lowmc_state_words64; ++i) {
        extended_masked_b[i] = b_base_value;
    }
    zeroTrailingBits((uint8_t *)extended_masked_b, params->stateSizeBits);

    xor64(extended_masked_b, bit_mask);

    Lowmc_state_words64 masked_w{ 0 };
    int rv = mpc_switch_.mpc_simulate(extended_masked_b, masked_current,
      masked_auth, current_tape_ptr, bit_mask_offset_, cmask_offset,
      amask_offset, msgs, masked_w, params);
    if (rv != EXIT_SUCCESS) {
        std::cerr << "Masked_tree_hash::mpc_simulate_sign: call to mpc_switch  "
                     "failed\n";
        return EXIT_FAILURE;
    }
    Lowmc_state_words64 masked_left{ 0 };
    xor64(masked_left, masked_w, masked_current);
    Lowmc_state_words64 masked_right{ 0 };
    xor64(masked_right, masked_w, masked_auth);

    if (Mpc_parameters::mpc_rounds_ < 5) {
        // Just for testing
        Lowmc_state_words64 c_mask = { 0 };
        if (cmask_offset != null_offset) {
            get_mask_from_tapes(c_mask, current_tape_ptr, cmask_offset, params);
        }

        Lowmc_state_words64 a_mask = { 0 };
        if (amask_offset != null_offset) {
            get_mask_from_tapes(a_mask, current_tape_ptr, amask_offset, params);
        }

        Lowmc_state_words64 i_mask{ 0 };
        if (intermediate_mask_offset_ != null_offset) {
            get_mask_from_tapes(
              i_mask, current_tape_ptr, intermediate_mask_offset_, params);
        }

        Lowmc_state_words64 left_mask{ 0 };
        xor64(left_mask, i_mask, c_mask);
        Lowmc_state_words64 right_mask{ 0 };
        xor64(right_mask, i_mask, a_mask);

        Lowmc_state_words64 left{ 0 };
        Lowmc_state_words64 right{ 0 };
        xor64(left, masked_left, left_mask);
        xor64(right, masked_right, right_mask);

        std::cout << "       left s: ";
        print_lowmc_state_words64(std::cout, left);
        std::cout << "\n      right s: ";
        print_lowmc_state_words64(std::cout, right);
        std::cout << "\n\n";
    }

    Lowmc_state_words64 remasked_first_input{ 0 };
    xor64(remasked_first_input, masked_left, first_input_mask_adjustment);

    rv = hash1b_.mpc_simulate(remasked_first_input, masked_right, masked_node,
      intermediate_mask_adjustment, current_tape_ptr, tmp_shares, msgs,
      masked_hash, params);
    if (rv != EXIT_SUCCESS) {
        std::cerr
          << "Masked_tree_hash::mpc_simulate_sign: call to hash1b failed\n";
        return EXIT_FAILURE;
    }

    return rv;
}

int Masked_tree_hash::mpc_simulate_and_verify(randomTape_t *current_tape_ptr,
  Lowmc_state_words64_const_ptr masked_current,
  Lowmc_state_words64_const_ptr masked_auth,
  Lowmc_state_words64_const_ptr masked_node, Tape_offset cmask_offset,
  Tape_offset amask_offset, [[maybe_unused]] shares_t *tmp_shares, msgs_t *msgs,
  Lowmc_state_words64_const_ptr extended_masked_b,
  Lowmc_state_words64_const_ptr first_input_mask_adjustment,
  Lowmc_state_words64_const_ptr intermediate_mask_adjustment,
  Lowmc_state_words64_ptr masked_hash, paramset_t *params) noexcept
{

    Lowmc_state_words64 masked_w{ 0 };
    int rv = mpc_switch_.mpc_simulate(extended_masked_b, masked_current,
      masked_auth, current_tape_ptr, bit_mask_offset_, cmask_offset,
      amask_offset, msgs, masked_w, params);
    if (rv != 0) {
        std::cerr << "MPC switch simulation failed, signature invalid\n";
        return EXIT_FAILURE;
    }

    Lowmc_state_words64 masked_left{ 0 };
    xor64(masked_left, masked_w, masked_current);

    Lowmc_state_words64 masked_right{ 0 };
    xor64(masked_right, masked_w, masked_auth);

    Lowmc_state_words64 remasked_first_input{ 0 };
    xor64(remasked_first_input, first_input_mask_adjustment, masked_left);

    rv = hash1b_.mpc_simulate(remasked_first_input, masked_right, masked_node,
      intermediate_mask_adjustment, current_tape_ptr, tmp_shares, msgs,
      masked_hash, params);
    if (rv != 0) {
        std::cerr << "MPC simulation failed, signature invalid\n";
        return EXIT_FAILURE;
    }

    return rv;
}

void Masked_tree_hash::reset()
{
    bit_mask_offset_ = null_offset;
    intermediate_mask_offset_ = null_offset;
}

// ************** Unmasked tree hash ***************

Tape_offset Unmasked_tree_hash::set_offsets(Tape_offset of) noexcept
{
    return hash1b_.set_offsets(of);
}

void Unmasked_tree_hash::compute_aux_tape(randomTape_t *current_tape_ptr,
  Lowmc_state_words64_const_ptr c_mask, Lowmc_state_words64_const_ptr a_mask,
  Index_parity child_row_index_parity,
  Node_address_state const &parent_node_addr,
  Lowmc_state_words64_const_ptr hash_mask,
  Lowmc_state_words64_ptr adjusted_first_mask,
  Lowmc_state_words64_ptr adjusted_intermediate_mask,
  paramset_t *params) noexcept
{
    Lowmc_state_words64_const_ptr left_mask;
    Lowmc_state_words64_const_ptr right_mask;
    if (child_row_index_parity == Index_parity::even) {
        left_mask = c_mask;
        right_mask = a_mask;
    } else {
        left_mask = a_mask;
        right_mask = c_mask;
    }

    hash1b_.compute_aux_tape(current_tape_ptr, left_mask, right_mask,
      parent_node_addr.node_mask64(), hash_mask, adjusted_first_mask,
      adjusted_intermediate_mask, params);
}

void Unmasked_tree_hash::get_aux_bits(
  uint8_t *aux_bits, uint32_t &aux_pos, randomTape_t *current_tape_ptr) noexcept
{
    hash1b_.get_aux_bits(aux_bits, aux_pos, current_tape_ptr);
}

void Unmasked_tree_hash::set_aux_bits(
  randomTape_t *current_tape_ptr, uint32_t &aux_pos, uint8_t *aux_bits) noexcept
{
    hash1b_.set_aux_bits(current_tape_ptr, aux_pos, aux_bits);
}

int Unmasked_tree_hash::mpc_simulate_sign(randomTape_t *current_tape_ptr,
  Lowmc_state_words64_const_ptr masked_current,
  Lowmc_state_words64_const_ptr masked_auth,
  Index_parity child_row_index_parity,
  Node_address_state const &parent_node_addr,
  [[maybe_unused]] shares_t *tmp_shares, msgs_t *msgs,
  Lowmc_state_words64_const_ptr first_input_mask_adjustment,
  Lowmc_state_words64_const_ptr intermediate_mask_adjustment,
  Lowmc_state_words64_ptr masked_left, Lowmc_state_words64_ptr masked_right,
  Lowmc_state_words64_ptr masked_hash, paramset_t *params) noexcept
{
    Lowmc_state_words64_const_ptr left_ptr{ nullptr };
    Lowmc_state_words64_const_ptr right_ptr{ nullptr };
    if (child_row_index_parity == Index_parity::even) {
        left_ptr = masked_current;
        right_ptr = masked_auth;
    } else {
        left_ptr = masked_auth;
        right_ptr = masked_current;
    }

    std::memcpy(masked_left, left_ptr, Mpc_parameters::lowmc_state_bytes_);
    std::memcpy(masked_right, right_ptr, Mpc_parameters::lowmc_state_bytes_);

    Lowmc_state_words64 remasked_first_input{ 0 };
    xor64(remasked_first_input, masked_left, first_input_mask_adjustment);

    int rv = hash1b_.mpc_simulate(remasked_first_input, masked_right,
      parent_node_addr.node_state64(), intermediate_mask_adjustment,
      current_tape_ptr, tmp_shares, msgs, masked_hash, params);
    if (rv != EXIT_SUCCESS) {
        std::cerr << "MPC simulation failed, signature invalid\n";
        return EXIT_FAILURE;
    }

    return rv;
}

int Unmasked_tree_hash::mpc_simulate_for_verify(randomTape_t *current_tape_ptr,
  Lowmc_state_words64_const_ptr masked_left,
  Lowmc_state_words64_const_ptr masked_right,
  Lowmc_state_words64_const_ptr masked_parent_node,
  [[maybe_unused]] shares_t *tmp_shares, msgs_t *msgs,
  Lowmc_state_words64_const_ptr first_input_mask_adjustment,
  Lowmc_state_words64_const_ptr intermediate_mask_adjustment,
  Lowmc_state_words64_ptr masked_hash, paramset_t *params) noexcept
{
    Lowmc_state_words64 remasked_first_input{ 0 };
    xor64(remasked_first_input, first_input_mask_adjustment, masked_left);

    int rv = hash1b_.mpc_simulate(remasked_first_input, masked_right,
      masked_parent_node, intermediate_mask_adjustment, current_tape_ptr,
      tmp_shares, msgs, masked_hash, params);
    if (rv != EXIT_SUCCESS) {
        std::cerr << "MPC simulation failed, signature invalid\n";
        return EXIT_FAILURE;
    }

    return rv;
}
