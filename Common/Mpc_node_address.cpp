/*******************************************************************************
 * File:        MPC_node_address.h
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



#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}

#include "Picnic_mpc_functions.h"
#include "Hbgs_param.h"
#include "Mpc_node_address.h"

Tape_offset Node_address_state::set_offsets(Tape_offset of) noexcept
{
    gt_index_offset_ = of;
    if (mask_gtree_only_) { return of + gt_offset_bits_; }
    mt_index_offset_ =
      gt_index_offset_ + static_cast<Tape_offset>(gt_index_bits);
    // Set the starting value for lsb_offset_
    lsb_mask_offset_ =
      mt_index_offset_ + static_cast<Tape_offset>(mt_index_bits - 1);

    return of + offset_bits_;
}

void Node_address_state::copy_data(Node_address_state const &nas) noexcept
{
    std::memcpy(state_, nas.state_, Mpc_parameters::lowmc_state_bytes_);
    std::memcpy(mask_, nas.mask_, Mpc_parameters::lowmc_state_bytes_);
    mask_gtree_only_ = nas.mask_gtree_only_;
    mask_applied_ = nas.mask_applied_;

    gt_index_offset_ = nas.gt_index_offset_;
    mt_index_offset_ = nas.mt_index_offset_;
    lsb_mask_offset_ = nas.lsb_mask_offset_;
}

Node_address_state::Node_address_state(Node_address_state const &nas) noexcept
{
    copy_data(nas);
}

Node_address_state &Node_address_state::operator=(
  Node_address_state const &nas) noexcept
{
    copy_data(nas);

    return *this;
}

void Node_address_state::set_initial_node_address(
  G_tree_address const &gt_addr, M_tree_address const &mt_addr) noexcept
{
    uint8_t *state_address = (uint8_t *)&state_[0];
    *state_address = gt_addr.row_;
    uint_to_mem(state_address + gt_index_pos_, gt_index_bytes, gt_addr.index_,
      store_big_endian_);
    *(state_address + m_tree_pos_) = mt_addr.m_tree_;
    *(state_address + mt_row_pos_) = mt_addr.row_;
    uint_to_mem(state_address + mt_index_pos_, mt_index_bytes, mt_addr.index_,
      store_big_endian_);
    mask_gtree_only_ = (mt_addr.m_tree_ == Public_parameters::k_);
    mask_applied_ = false;
}

void Node_address_state::set_and_apply_initial_mask(
  randomTape_t *tapes, size_t t) noexcept
{
    if (mask_applied_) { xor64(state_, mask_); }
    tapes[t].pos = gt_index_offset_;
    uint8_t *mask_address = (uint8_t *)&mask_[0];
    tapesToParityBits(
      (uint32_t *)(mask_address + gt_index_pos_), gt_index_bits, &tapes[t]);
    if (!mask_gtree_only_) {
        tapesToParityBits(
          (uint32_t *)(mask_address + mt_index_pos_), mt_index_bits, &tapes[t]);
    }

    // Reset the offset for the lsb
    lsb_mask_offset_ =
      static_cast<Tape_offset>(mt_index_offset_ + mt_index_bits - 1);

    xor64(state_, mask_);
    mask_applied_ = true;
}

void Node_address_state::set_mt_index(Mt_index_type index) noexcept
{
    if (mask_applied_ && !mask_gtree_only_) { xor64(state_, mask_); }

    auto state_address = (uint8_t *)&state_[0];
    uint_to_mem(
      state_address + mt_index_pos_, mt_index_bytes, index, store_big_endian_);

    if (mask_applied_ && !mask_gtree_only_) { xor64(state_, mask_); }
}

void Node_address_state::set_masked_mt_index(
  Mt_index_type index, Mt_index_type mask) noexcept
{
    if (mask_applied_ && !mask_gtree_only_) { xor64(state_, mask_); }

    auto state_address = (uint8_t *)&state_[0];
    uint_to_mem(
      state_address + mt_index_pos_, mt_index_bytes, index, store_big_endian_);

    auto mask_address = (uint8_t *)&mask_[0];
    uint_to_mem(
      mask_address + mt_index_pos_, mt_index_bytes, mask, store_big_endian_);

    if (mask_applied_ && !mask_gtree_only_) { xor64(state_, mask_); }
}

Mt_index_type Node_address_state::get_mt_index() const noexcept
{
    assertm(!mask_applied_ | mask_gtree_only_,
      "Node_address_state::get_mt_index: the index must be unmasked");

    Mt_index_type mti{ 0 };
    auto state_address = (uint8_t *)&state_[0];
    mem_to_uint(
      mti, state_address + mt_index_pos_, mt_index_bytes, store_big_endian_);

    return mti;
}

Mt_row_type Node_address_state::get_mt_row() const noexcept
{
    Mt_row_type mtr{ 0 };
    auto state_address = (uint8_t *)&state_[0];
    mtr = *(state_address + mt_row_pos_);// Mt_row_type is uint8_t

    return mtr;
}

void Node_address_state::update_mt_row_and_index() noexcept
{
    auto state_address = (uint8_t *)&state_[0];
    Mt_index_type index{ 0 };
    mem_to_uint(
      index, state_address + mt_index_pos_, mt_index_bytes, store_big_endian_);
    index /= 2;
    uint_to_mem(
      state_address + mt_index_pos_, mt_index_bytes, index, store_big_endian_);
    lsb_mask_offset_--;
    (*(state_address + mt_row_pos_))--;
    if (mask_gtree_only_) { return; }

    auto mask_address = (uint8_t *)&mask_[0];
    Mt_index_type mask{ 0 };
    mem_to_uint(
      mask, mask_address + mt_index_pos_, mt_index_bytes, store_big_endian_);
    mask /= 2;
    uint_to_mem(
      mask_address + mt_index_pos_, mt_index_bytes, mask, store_big_endian_);
}

uint8_t Node_address_state::lsb_mask() const noexcept
{
    if (mt_index_offset_ == null_offset) { return 0x00; }

    if (!mask_applied_) {
        std::cerr << "Warning: lsb_mask: no mask applied yet\n";
        return 0x00;
    }

    auto mask_address = (uint8_t *)&mask_[0];
    Mt_index_type mask{ 0 };
    mem_to_uint(
      mask, mask_address + mt_index_pos_, mt_index_bytes, store_big_endian_);

    return mask % 2;
}

uint8_t Node_address_state::lsb_masked_bit() const noexcept
{
    if (mt_index_offset_ != null_offset && !mask_applied_) {
        std::cerr << "Warning: lsb_masked_bit: no mask applied yet\n";
    }

    auto state_address = (uint8_t *)&state_[0];
    Mt_index_type index{ 0 };
    mem_to_uint(
      index, state_address + mt_index_pos_, mt_index_bytes, store_big_endian_);

    return index % 2;
}

uint8_t Node_address_state::lsb_bit() const noexcept
{
    return lsb_mask() ^ lsb_masked_bit();
}

Index_parity Node_address_state::lsb_parity() const noexcept
{
    return static_cast<Index_parity>(lsb_bit());
}

uint16_t Node_address_state::lsb_shares(randomTape_t *tapes, size_t t) const
  noexcept
{
    uint8_t bmask{ 0 };
    uint16_t eb_shares{ 0 };
    if (lsb_mask_offset_ != null_offset) {
        tapes[t].pos = lsb_mask_offset_;
        eb_shares = tapesToWord(&tapes[t]);
        bmask = static_cast<uint8_t>(parity16(eb_shares));
    }

    if (bmask != lsb_mask()) {
        std::cerr << "Warning: lsb_shares: inconsitent values for mask\n";
    }
    return eb_shares;
}

void Node_address_state::reset()
{
    std::memset(state_, 0, Mpc_parameters::lowmc_state_bytes_);
    std::memset(mask_, 0, Mpc_parameters::lowmc_state_bytes_);
    mask_gtree_only_ = false;
    mask_applied_ = false;

    gt_index_offset_ = null_offset;
    mt_index_offset_ = null_offset;
    lsb_mask_offset_ = null_offset;
}

void Node_address_state::put_node_data(std::ostream &os) const
{
    Lowmc_state_words64 st{ 0 };
    std::memcpy(st, state_, Mpc_parameters::lowmc_state_bytes_);
    if (mask_applied_) { xor64(st, mask_); }
    auto state_address = (uint8_t *)&st[0];

    G_tree_address gt_addr{};
    gt_addr.row_ = *state_address;
    mem_to_uint(gt_addr.index_, state_address + gt_index_pos_, gt_index_bytes,
      store_big_endian_);

    M_tree_address mt_addr{};

    mem_to_uint(mt_addr.index_, state_address + mt_index_pos_, mt_index_bytes,
      store_big_endian_);
    mt_addr.m_tree_ = *(state_address + m_tree_pos_);
    mt_addr.row_ = *(state_address + mt_row_pos_);

    os << std::hex << "G_tree address: row: 0x" << 0 + gt_addr.row_
       << " index: 0x" << gt_addr.index_ << '\n'
       << std::dec;

    os << "M_tree address: tree: " << 0 + mt_addr.m_tree_
       << " row: " << 0 + mt_addr.row_ << " index: " << mt_addr.index_ << '\n';

    os << std::boolalpha << "Mask G_tree only: " << mask_gtree_only_
       << "\tMask applied: " << mask_applied_ << '\n';
}

void Node_address_state::update_gt_row_and_index() noexcept
{
    auto state_address = (uint8_t *)&state_[0];
    Gt_index_type index{ 0 };
    mem_to_uint(
      index, state_address + gt_index_pos_, gt_index_bytes, store_big_endian_);
    index /= Public_parameters::q_;
    uint_to_mem(
      state_address + gt_index_pos_, gt_index_bytes, index, store_big_endian_);
    (*(state_address + gt_row_pos_))--;

    auto mask_address = (uint8_t *)&mask_[0];
    Gt_index_type mask{ 0 };
    mem_to_uint(
      mask, mask_address + gt_index_pos_, gt_index_bytes, store_big_endian_);
    mask /= Public_parameters::q_;
    uint_to_mem(
      mask_address + gt_index_pos_, gt_index_bytes, mask, store_big_endian_);
}
