/*******************************************************************************
 * File:        Mpc_tree_hash.h
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



#ifndef MPC_TREE_HASH_H
#define MPC_TREE_HASH_H

#include "Hbgs_param.h"
#include "Mpc_lowmc64.h"
#include "Mpc_switch.h"
#include "Mpc_hash1.h"
#include "Mpc_working_data.h"
#include "Mpc_signature_utils.h"
#include "Mpc_parameters.h"
#include "Mpc_node_address.h"

class Masked_tree_hash
{
  public:
    Masked_tree_hash() = default;
    Tape_offset set_offsets(Tape_offset of) noexcept;
    void compute_aux_tape(randomTape_t *current_tape_ptr,
      Lowmc_state_words64_const_ptr c_mask,
      Lowmc_state_words64_const_ptr a_mask,
      Lowmc_state_words64_const_ptr node_mask,
      Lowmc_state_words64_const_ptr hash_mask,
      Lowmc_state_words64_ptr adjusted_first_mask,
      Lowmc_state_words64_ptr adjusted_intermediate_mask,
      paramset_t *params) noexcept;
    void get_aux_bits(uint8_t *aux_bits, uint32_t &aux_pos,
      randomTape_t *current_tape_ptr) noexcept;
    void set_aux_bits(randomTape_t *current_tape_ptr, uint32_t &aux_pos,
      uint8_t *aux_bits) noexcept;
    int mpc_simulate_sign(randomTape_t *current_tape_ptr,
      Lowmc_state_words64_const_ptr masked_current,
      Lowmc_state_words64_const_ptr masked_auth,
      Lowmc_state_words64_const_ptr masked_node, Tape_offset cmask_offset,
      Tape_offset amask_offset, uint8_t bit_value,
      [[maybe_unused]] shares_t *tmp_shares, msgs_t *msgs,
      Lowmc_state_words64_ptr extended_masked_b,
      Lowmc_state_words64_const_ptr first_input_mask_adjustment,
      Lowmc_state_words64_const_ptr intermediate_mask_adjustment,
      Lowmc_state_words64_ptr masked_hash, paramset_t *params) noexcept;
    int mpc_simulate_and_verify(randomTape_t *current_tape_ptr,
      Lowmc_state_words64_const_ptr masked_current,
      Lowmc_state_words64_const_ptr masked_auth,
      Lowmc_state_words64_const_ptr masked_node, Tape_offset cmask_offset,
      Tape_offset amask_offset, [[maybe_unused]] shares_t *tmp_shares,
      msgs_t *msgs, Lowmc_state_words64_const_ptr extended_masked_b,
      Lowmc_state_words64_const_ptr first_input_mask_adjustment,
      Lowmc_state_words64_const_ptr intermediate_mask_adjustment,
      Lowmc_state_words64_ptr masked_hash, paramset_t *params) noexcept;
    void set_mpc_indices(size_t inp, size_t mpc_inp, size_t outp);

    void reset();

    constexpr static Tape_offset local_offset_bits_ =
      2 * Mpc_parameters::lowmc_state_bits_;

    constexpr static Tape_offset offset_bits_ =
      Mpc_switch::offset_bits_ + Hash1b::offset_bits_ + local_offset_bits_;

    constexpr static Tape_offset tape_bits_ =
      Mpc_switch::tape_bits_ + Hash1b::tape_bits_;

    constexpr static Tape_offset aux_bits_ =
      Mpc_switch::aux_bits_ + Hash1b::aux_bits_;

  private:
    Tape_offset bit_mask_offset_{ null_offset };
    Tape_offset intermediate_mask_offset_{ null_offset };

    Mpc_switch mpc_switch_{};
    Hash1b hash1b_{};
};

class Unmasked_tree_hash
{
  public:
    Unmasked_tree_hash() = default;
    Tape_offset set_offsets(Tape_offset of) noexcept;
    void compute_aux_tape(randomTape_t *current_tape_ptr,
      Lowmc_state_words64_const_ptr c_mask,
      Lowmc_state_words64_const_ptr a_mask, Index_parity child_row_index_parity,
      Node_address_state const &parent_node_addr,
      Lowmc_state_words64_const_ptr hash_mask,
      Lowmc_state_words64_ptr adjusted_first_mask,
      Lowmc_state_words64_ptr adjusted_intermediate_mask,
      paramset_t *params) noexcept;
    void get_aux_bits(uint8_t *aux_bits, uint32_t &aux_pos,
      randomTape_t *current_tape_ptr) noexcept;
    void set_aux_bits(randomTape_t *current_tape_ptr, uint32_t &aux_pos,
      uint8_t *aux_bits) noexcept;
    int mpc_simulate_sign(randomTape_t *current_tape_ptr,
      Lowmc_state_words64_const_ptr masked_current,
      Lowmc_state_words64_const_ptr masked_auth,
      Index_parity child_row_index_parity,
      Node_address_state const &parent_node_addr,
      [[maybe_unused]] shares_t *tmp_shares, msgs_t *msgs,
      Lowmc_state_words64_const_ptr first_input_mask_adjustment,
      Lowmc_state_words64_const_ptr intermediate_mask_adjustment,
      Lowmc_state_words64_ptr masked_left, Lowmc_state_words64_ptr masked_right,
      Lowmc_state_words64_ptr masked_hash, paramset_t *params) noexcept;
    int mpc_simulate_for_verify(randomTape_t *current_tape_ptr,
      Lowmc_state_words64_const_ptr masked_left,
      Lowmc_state_words64_const_ptr masked_right,
      Lowmc_state_words64_const_ptr masked_parent_node,
      [[maybe_unused]] shares_t *tmp_shares, msgs_t *msgs,
      Lowmc_state_words64_const_ptr first_input_mask_adjustment,
      Lowmc_state_words64_const_ptr intermediate_mask_adjustment,
      Lowmc_state_words64_ptr masked_hash, paramset_t *params) noexcept;
    void set_mpc_indices(size_t inp, size_t mpc_inp, size_t outp);
    void reset() {}

    constexpr static Tape_offset offset_bits_ = Hash1b::offset_bits_;

    constexpr static Tape_offset tape_bits_ = Hash1b::tape_bits_;

    constexpr static Tape_offset aux_bits_ = Hash1b::aux_bits_;

  private:
    Hash1b hash1b_{};
};

#endif
