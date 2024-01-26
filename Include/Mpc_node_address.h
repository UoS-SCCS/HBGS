/*******************************************************************************
 * File:        Mpc_node_address.h
 * Description: Code for the node address and its mask
 *
 * Author:      Chris Newton
 *
 * Created:     Friday 25 March 2022
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



#ifndef MPC_NODE_ADDR_H
#define MPC_NODE_ADDR_H

#include <cstring>

//#include "picnic.h"
// extern "C" {
//#include "picnic_types.h"
//#include "picnic3_impl.h"
//}

#include "Hbgs_param.h"
#include "Mem_uint.h"
#include "Lowmc64.h"

struct randomTape_t;

struct G_tree_address
{
    Gt_row_type row_{ 0 };
    Gt_index_type index_{ 0 };
};

struct M_tree_address
{
    Mt_tree_type m_tree_{ 0 };
    Mt_row_type row_{ 0 };
    Mt_index_type index_{ 0 };
};

// Used for the extra information used when building the trees
// Only part of the data needs to be masked. Particularly
// Initially the mask is 0 and the state is effectively unmasked,
// this is good at the start. Once a mask is set the state is
// masked as well. Note: we may need to keep a copy ready for
// re-masking.
// important is the 'index' at the current level of the Merkle
// tree, the least significant bit of this index is used to
// determine how to combine the current hash value with the
// next value from the authpath.

class Node_address_state
{
  public:
    constexpr static bool store_big_endian_ =
      Public_parameters::use_big_endian_;
    Node_address_state() = default;
    Node_address_state(Node_address_state const &nas) noexcept;
    Node_address_state &operator=(Node_address_state const &nas) noexcept;
    Tape_offset set_offsets(Tape_offset of) noexcept;
    void set_initial_node_address(
      G_tree_address const &gt_addr, M_tree_address const &mf_addr) noexcept;
    void set_and_apply_initial_mask(randomTape_t *tapes, size_t t) noexcept;
    // Update the Merkle tree row, mt_index and the corresponding index
    // mask.
    void update_mt_row_and_index() noexcept;
    void set_mt_index(Mt_index_type index) noexcept;
    void set_masked_mt_index(Mt_index_type index, Mt_index_type mask) noexcept;
    Mt_index_type get_mt_index() const noexcept;
    std::pair<Mt_index_type, Mt_index_type> get_masked_mt_index() const
      noexcept;
    Mt_row_type get_mt_row() const noexcept;
    // Update the Group tree row and index and the index mask
    void update_gt_row_and_index() noexcept;
    Lowmc_state_words64_const_ptr node_state64() const { return state_; }
    Lowmc_state_words64_ptr node_state64() { return state_; }
    Lowmc_state_words64_const_ptr node_mask64() const { return mask_; }
    Lowmc_state_words64_ptr node_mask64() { return mask_; }
    Lowmc_state_words_const_ptr node_state() const
    {
        return (uint32_t const *)state_;
    }
    Lowmc_state_words_ptr node_state() { return (uint32_t *)state_; }
    Lowmc_state_words_const_ptr node_mask() const
    {
        return (uint32_t const *)mask_;
    }
    Lowmc_state_words_ptr node_mask() { return (uint32_t *)mask_; }
    Index_parity lsb_parity() const noexcept;
    uint8_t lsb_mask() const noexcept;
    uint8_t lsb_bit() const noexcept;
    uint8_t lsb_masked_bit() const noexcept;
    uint16_t lsb_shares(randomTape_t *tapes, size_t t) const noexcept;
    // Reset to the starting value (mainly for testing)
    void reset();
    // Mainly for testing
    void put_node_data(std::ostream &os) const;
    // Tape offsets for the masked parts of the state
    constexpr static Tape_offset offset_bits_{ gt_index_bits + mt_index_bits };
    constexpr static Tape_offset gt_offset_bits_{ gt_index_bits };

  private:
    Lowmc_state_words64 state_{ 0 };
    Lowmc_state_words64 mask_{ 0 };
    bool mask_applied_{ false };
    bool mask_gtree_only_{ false };

    // Byte positions in the state
    constexpr static size_t gt_row_pos_{ 0 };
    constexpr static size_t gt_index_pos_{ gt_row_bytes };
    constexpr static size_t m_tree_pos_{ gt_index_pos_ + gt_index_bytes };
    constexpr static size_t mt_row_pos_{ m_tree_pos_ + sizeof(Mt_tree_type) };
    constexpr static size_t mt_index_pos_{ mt_row_pos_ + sizeof(Mt_row_type) };

    Tape_offset gt_index_offset_{ null_offset };
    Tape_offset mt_index_offset_{ null_offset };
    // lsb_index is relative to mt_index_offset_. It is
    // adjusted as the mt_index is shifted as we move up
    // the tree so that the shares for this bit are
    // correctly assigned from the tapes. If we shift the value
    // and its mask left by one bit, lsb_offset_ must be
    // decreased by one.
    Tape_offset lsb_mask_offset_{ null_offset };

    void copy_data(Node_address_state const &nas) noexcept;
};


#endif
