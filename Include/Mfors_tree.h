/*******************************************************************************
 * File:        Mfors_tree.h
 * Description: The code for the MFORS trees used in the system
 *
 * Author:      Chris Newton
 * Created:     Monday 9 May 2022
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



#ifndef MFORS_TREE_H
#define MFORS_TREE_H

#include <array>
#include <iostream>
#include <cassert>

#include "Hbgs_param.h"
#include "Lowmc64.h"
#include "Hash2_64.h"
#include "Merkle_tree.h"
#include "Mpc_parameters.h"
#include "Mpc_node_address.h"

using Signing_indices = Mt_index_type[Public_parameters::k_];
using Signing_indices_ptr = Mt_index_type *;
using Signing_indices_const_ptr = Mt_index_type const *;

void print_signing_indices(std::ostream &os, Signing_indices_const_ptr si);

bool read_signing_indices(std::ifstream &is, Signing_indices_ptr si);

// The number of nodes in the parent row, given the number of children
// Used for truncated trees
constexpr uint32_t n_parent_row_nodes(uint32_t n_child_row_nodes)
{
    return (n_child_row_nodes % 2 == 1) ? (n_child_row_nodes + 1) / 2
                                        : n_child_row_nodes / 2;
}

// The total number of nodes in the top tree - used for truncated trees
constexpr uint32_t n_top_tree_nodes(uint32_t k, uint32_t height)
{
    uint32_t n_r = k;
    uint32_t total = n_r;
    for (uint32_t r = height; r > 0; --r) {//
        n_r = n_parent_row_nodes(n_r);
        total += n_r;
    }
    return total;
}

void signing_indices_from_hash2(Signing_indices &si, H2_data64 const &h2d);

constexpr static auto top_tree_param =
  calculate_tree_height(Public_parameters::k_, 2);

struct Top_authpath
{
    constexpr static uint8_t height_ = top_tree_param.first;
    G_tree_address gt_addr_{};
    // The top tree has Merkle tree number k
    const Mt_tree_type m_tree_{ Public_parameters::k_ };
    // The base Merkle tree number defines the node indices for the top tree
    Mt_index_type base_tree_no_{ 0 };// The top tree leaf index
    Lowmc_state_words64 base_tree_root_{ 0 };// The leaf of the top tree
    size_t path_size_{ 0 };
    std::array<Lowmc_state_words64, height_> top_path_;
};

struct Mfors_authpath
{
    Base_authpath base_path_{};
    Top_authpath top_path_{};
};

using Mfors_authpath_ptr = Mfors_authpath *;
using Mfors_authpath_const_ptr = Mfors_authpath const *;

struct Mfors_tree_paths
{
    constexpr static Mt_row_type n_paths_ = Public_parameters::k_;
    Lowmc_state_words64 input_hash_{ 0 };
    Signing_indices indices_{};
    Mfors_authpath authpaths_[n_paths_];
};


// The situation for the current position on the top authpath:
//     normal - inside the tree, just do the hash
//       hash - at the edge, but at an odd node so do the hash
//       lift - at the edge, but at an even node so lift to the next row
enum class Top_path_state { normal, hash, lift };


Top_path_state top_path_state(uint32_t n_row_nodes, Mt_index_type mt_index);

// For debugging
std::string top_path_state_string(Top_path_state st);


class Mfors_tree
{
  public:
    enum Status {
        uninitialised,
        initialised,
        leaves_set,
        nodes_set,
        paths_set
    };
    Mfors_tree() = delete;
    Mfors_tree(Lowmc_state_words64_const_ptr master_seed,
      G_tree_address const &gt_addr, paramset_t *params) noexcept;
    Mfors_tree(Mfors_tree const &) = delete;
    Mfors_tree &operator=(Mfors_tree const &) = delete;
    constexpr static uint16_t k_ = Public_parameters::k_;
    constexpr static uint8_t height_ = top_tree_param.first;
    constexpr static uint32_t n_tree_nodes_ =
      n_top_tree_nodes(Public_parameters::k_, height_);
    // calculate the leaves of the top tree (roots of the corresponding Merkle
    // tree) if indices is not a nullptr also calculate the base authpath for
    // the Merkle trees
    bool calculate_leaves(Signing_indices_const_ptr indices) noexcept;
    // calculate the nodes of the top tree - the leaves must already be set
    bool calculate_nodes() noexcept;
    bool calculate_top_authpaths() noexcept;
    bool get_root(Lowmc_state_words64_ptr root) const noexcept;
    Mfors_authpath_const_ptr get_authpaths() const noexcept;

  private:
    Status status_{ uninitialised };
    G_tree_address gt_addr_{};
    paramset_t paramset_;

    // We are truncating the tree so use these to keep track of where we are
    std::array<size_t, height_ + 1> row_start_indices_{ 0 };
    std::array<size_t, height_ + 1> row_lengths_{ 0 };
    Lowmc_state_words64 tree_data_[n_tree_nodes_];
    Lowmc_state_words64 seed_{ 0 };
    paramset_t *params_{ nullptr };
    bool generate_authpaths_{ false };
    Mfors_authpath authpaths_[k_];

    void assign_row_data() noexcept;
    bool get_top_authpath(Mt_tree_type tree_no) noexcept;
};
    void copy_top_authpath(Top_authpath &dest, Top_authpath const &srce);

bool check_top_authpath(Lowmc_state_words64_const_ptr root,
  Top_authpath const &path, paramset_t *params) noexcept;

void copy_mfors_authpath(Mfors_authpath &dest, Mfors_authpath const &srce);

bool check_mfors_authpaths(Lowmc_state_words64_const_ptr root,
  Mfors_authpath_const_ptr paths, paramset_t *params);

void print_mfors_authpaths(std::ostream &os, Mfors_authpath_const_ptr paths);

bool read_mfors_authpaths(std::ifstream &is, Mfors_authpath_ptr paths);


#endif
