/*******************************************************************************
 * File:        Merkle_trees_.h
 * Description: The code for the Merkle trees used in the system
 *
 * Author:      Chris Newton
 * Created:     Friday 5 May 2022
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

#include "Hbgs_lowmc_hash.h"
#include "Merkle_tree.h"

//#define DEBUG_MERKLE

void tree_path_hash(Lowmc_state_words64_ptr tree_hash,
  Lowmc_state_words64_const_ptr authpath, Index_parity child_index_parity,
  Node_address_state const &parent_node_addr, paramset_t *params) noexcept
{
    if (child_index_parity == Index_parity::even) {
        hash1b64(tree_hash, tree_hash, authpath,
          parent_node_addr.node_state64(), params);
    } else {
        hash1b64(tree_hash, authpath, tree_hash,
          parent_node_addr.node_state64(), params);
    }
}

Merkle_tree::Merkle_tree(Lowmc_state_words64_const_ptr seed,
  G_tree_address const &gt_addr, Mt_tree_type mt_tree,
  paramset_t *params) noexcept
  : gt_addr_{ gt_addr }, mt_tree_{ mt_tree }, params_(params)
{
    std::memcpy(seed_, seed, Mpc_parameters::lowmc_state_bytes_);

    M_tree_address mt_addr{ mt_tree, d_, 0 };
    Node_address_state node_addr{};

    Lowmc_state_words64 leaf_precursor{ 0 };
    auto n_row_nodes = static_cast<size_t>(std::pow(2, d_));
    size_t row_start_index = n_row_nodes - 1U;
    // Do the bottom row
    for (size_t row_index = 0; row_index < n_row_nodes; row_index++) {
        mt_addr.index_ = static_cast<Mt_index_type>(row_index);
        generate_leaf_precursor(leaf_precursor, mt_addr.index_);
        node_addr.set_initial_node_address(gt_addr_, mt_addr);
        hash1a64(tree_data_[row_start_index + row_index], leaf_precursor,
          node_addr.node_state64(), params_);
#ifdef DEBUG_MERKLE
        if (d_ < 5) {
            std::cout << "\n " << 0 + mt_addr.m_tree_ << "\t "
                      << 0 + mt_addr.row_ << '\t' << row_index << '\t';
            print_lowmc_state_bytes(
              std::cout, (uint8_t *)tree_data_[row_start_index + row_index]);
        }
#endif
    }
#ifdef DEBUG_MERKLE
    if (d_ < 5) { std::cout << '\n'; }
#endif
    size_t left_index{ 0 };
    size_t right_index{ 0 };
    size_t child_row_start_index = row_start_index;
    for (uint8_t row = d_ - 1; row < d_; row--) {
        n_row_nodes = static_cast<uint16_t>(std::pow(2, row));
        row_start_index = n_row_nodes - 1U;
        for (size_t row_index = 0; row_index < n_row_nodes; row_index++) {
            left_index = child_row_start_index + 2U * row_index;
            right_index = left_index + 1U;
            mt_addr.row_ = row;
            mt_addr.index_ = static_cast<Mt_index_type>(row_index);
            node_addr.set_initial_node_address(gt_addr_, mt_addr);
            hash1b64(tree_data_[row_start_index + row_index],
              tree_data_[left_index],
              tree_data_[right_index],
              node_addr.node_state64(),
              params_);
#ifdef DEBUG_MERKLE
            if (d_ < 5) {
                std::cout << "\n " << 0 + mt_addr.m_tree_ << '\t'
                          << 0 + mt_addr.row_ << '\t' << mt_addr.index_ << '\t';
                print_lowmc_state_bytes(std::cout,
                  (uint8_t *)tree_data_[row_start_index + row_index]);
            }
#endif
        }
        child_row_start_index = row_start_index;
#ifdef DEBUG_MERKLE
        if (d_ < 5) { std::cout << '\n'; }
#endif
    }

#ifdef DEBUG_MERKLE
    std::cout << "\n\nRoot node:\t";
    print_lowmc_state_bytes(std::cout, (uint8_t *)tree_data_[0]);
    std::cout << '\n';
#endif
}

bool Merkle_tree::get_authpath(Mt_index_type leaf_index, Base_authpath &path)
{
    path.gt_addr_ = gt_addr_;
    path.m_tree_ = mt_tree_;
    path.leaf_index_ = leaf_index;
    uint8_t row = d_;
    auto n_row_nodes = static_cast<size_t>(std::pow(2, d_));
    if (leaf_index > n_row_nodes - 1) {
        std::cerr << "Error: leaf index in get_authpath too large\n";
        return false;
    }
    generate_leaf_precursor(path.leaf_precursor_, path.leaf_index_);
#ifdef DEBUG_MERKLE
    if (d_ < 5) {
        std::cout << '\n' << 0 + row << '\t' << leaf_index << '\t';
        print_lowmc_state_bytes(std::cout, (uint8_t *)path.leaf_precursor_);
    }
#endif
    size_t row_start_index = n_row_nodes - 1U;
    for (uint8_t i = 0; i < d_; ++i) {
        uint8_t leaf_lsb = leaf_index % 2;
        if (leaf_lsb == 0) {
            std::memcpy(path.path_[i],
              tree_data_[row_start_index + leaf_index + 1],
              Mpc_parameters::lowmc_state_bytes_);
        } else {
            std::memcpy(path.path_[i],
              tree_data_[row_start_index + leaf_index - 1],
              Mpc_parameters::lowmc_state_bytes_);
        }
#ifdef DEBUG_MERKLE
        if (d_ < 5) {
            std::cout << '\n'
                      << 0 + row << '\t'
                      << (leaf_lsb == 0 ? leaf_index + 1 : leaf_index - 1)
                      << '\t';
            print_lowmc_state_bytes(std::cout, (uint8_t *)path.path_[i]);
        }
#endif
        row--;
        leaf_index /= 2;
        n_row_nodes = static_cast<size_t>(std::pow(2, row));
        row_start_index = n_row_nodes - 1U;
    }

#ifdef DEBUG_MERKLE
    if (d_ < 5) { std::cout << '\n'; }
#endif
    return true;
}

void Merkle_tree::generate_leaf_precursor(
  Lowmc_state_words64_ptr leaf_precursor, Mt_index_type leaf_index)
{
    constexpr static size_t leaf_address_size =
      gt_row_bytes + gt_index_bytes + mt_tree_bytes + mt_index_bytes;
    uint8_t leaf_address[leaf_address_size];
    generate_leaf_address(leaf_address, leaf_index);
    Hash_data hd{ leaf_address_size, leaf_address };
    lowmc_state_from_hash((uint8_t *)leaf_precursor, params_, seed_, hd);
}

void Merkle_tree::generate_leaf_address(
  uint8_t *leaf_address, Mt_index_type leaf_index)
{
    uint8_t *next_address = leaf_address;
    *next_address = gt_addr_.row_;
    next_address += gt_row_bytes;
    uint_to_mem(next_address, gt_index_bytes, gt_addr_.index_,
      Public_parameters::use_big_endian_);
    next_address += gt_index_bytes;
    *next_address = mt_tree_;
    next_address += mt_tree_bytes;
    uint_to_mem(next_address, mt_index_bytes, leaf_index,
      Public_parameters::use_big_endian_);
}

bool check_base_authpath(Lowmc_state_words64_const_ptr root,
  Base_authpath const &path, paramset_t *params) noexcept
{
    Node_address_state node_addr{};
    G_tree_address gt_addr = path.gt_addr_;
    M_tree_address mf_addr = { path.m_tree_, Base_authpath::depth_,
        path.leaf_index_ };
    node_addr.set_initial_node_address(gt_addr, mf_addr);
#ifdef DEBUG_MERKLE
    if (Base_authpath::depth_ < 5) {
        std::cout << "ca: initial_node_address: ";
        print_lowmc_state_words(std::cout, node_addr.node_state());
        std::cout << "\nca:    initial_node_mask: ";
        print_lowmc_state_words(std::cout, node_addr.node_mask());
        std::cout << "\n\n Node:\t\t";
        print_lowmc_state_bytes(std::cout, (uint8_t *)node_addr.node_state());
    }
#endif
    Lowmc_state_words64 tree_hash{ 0 };
    hash1a64(tree_hash, path.leaf_precursor_, node_addr.node_state64(), params);
#ifdef DEBUG_MERKLE
    if (Base_authpath::depth_ < 5) {
        std::cout << "\n Hash:\t\t";
        print_lowmc_state_bytes(std::cout, (uint8_t *)tree_hash);
    }
#endif
    Index_parity child_row_index_parity;
    bool error_detected{ false };
    for (uint8_t i = 0; i < Base_authpath::depth_; ++i) {
        child_row_index_parity = node_addr.lsb_parity();
        node_addr.update_mt_row_and_index();
        tree_path_hash(
          tree_hash, path.path_[i], child_row_index_parity, node_addr, params);

#ifdef DEBUG_MERKLE
        if (Base_authpath::depth_ < 5) {
            std::cout << "\n Hash:\t" << i + 0 << '\t';
            print_lowmc_state_bytes(std::cout, (uint8_t *)tree_hash);
        }
#endif
    }
#ifdef DEBUG_MERKLE
    if (Base_authpath::depth_ < 5) { std::cout << '\n'; }
#endif
    if (error_detected
        || std::memcmp(root, tree_hash, Mpc_parameters::lowmc_state_bytes_)
             != 0) {
        return false;
    }

    return true;
}

void copy_base_authpath(Base_authpath &dest, Base_authpath const &srce)
{
    dest.gt_addr_ = srce.gt_addr_;
    dest.m_tree_ = srce.m_tree_;
    dest.leaf_index_ = srce.leaf_index_;
    std::memcpy(dest.leaf_precursor_, srce.leaf_precursor_,
      Mpc_parameters::lowmc_state_bytes_);
    for (size_t i = 0; i < srce.path_.size(); ++i) {
        std::memcpy(
          dest.path_[i], srce.path_[i], Mpc_parameters::lowmc_state_bytes_);
    }
}
