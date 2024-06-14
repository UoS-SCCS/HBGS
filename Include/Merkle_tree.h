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



#ifndef MERKLE_TREES_H
#define MERKLE_TREES_H

#include <array>
#include <cassert>

#include "Hbgs_param.h"
#include "Lowmc32.h"
#include "Lowmc64.h"
#include "Mpc_parameters.h"
#include "Mpc_node_address.h"


static_assert(
  Tree_parameters::d_ <= 16, "The Merkle tree depth must be <=16");

void tree_path_hash(Lowmc_state_words64_ptr tree_hash,
  Lowmc_state_words64_const_ptr authpath, Index_parity child_lsb_parity,
  Node_address_state const &parent_node_addr, paramset_t *params) noexcept;

struct Base_authpath
{
    constexpr static uint8_t depth_ = Tree_parameters::d_;
    G_tree_address gt_addr_{};
    Mt_tree_type m_tree_{ 0 };
    Mt_index_type leaf_index_{ 0 };
    Lowmc_state_words64 leaf_precursor_{ 0 };
    std::array<Lowmc_state_words64, depth_> path_;
};

void copy_base_authpath(Base_authpath &dest, Base_authpath const &srce);

class Merkle_tree
{
  public:
    Merkle_tree() = delete;
    Merkle_tree(Lowmc_state_words64_const_ptr seed,
      G_tree_address const &gt_addr, Mt_tree_type mt_tree,
      paramset_t *params) noexcept;
    Merkle_tree(Merkle_tree const &) = delete;
    Merkle_tree &operator=(Merkle_tree const &) = delete;
    constexpr static uint8_t d_{ Tree_parameters::d_ };
    static_assert(sizeof(size_t) > sizeof(Mt_index_type),
      "sizeof(size_t) must be > sizeof(Mt_index_type)");
    constexpr static auto n_tree_nodes_ =
      static_cast<size_t>(Pow<2, d_ + 1U>::Value - 1U);
    constexpr static auto n_tree_leaves_ =
      static_cast<size_t>(Pow<2, d_>::Value);
    void get_root(Lowmc_state_words64_ptr root) const
    {
        memcpy(root, tree_data_[0], Lowmc_parameters::lowmc_state_bytes_);
    }
    bool get_authpath(Mt_index_type leaf_index, Base_authpath &path);

  private:
    G_tree_address gt_addr_{};
    Mt_tree_type mt_tree_{ 0 };

    // M_tree_address mt_addr_{};

    Lowmc_state_words64 tree_data_[n_tree_nodes_];
    Lowmc_state_words64 seed_{ 0 };
    paramset_t *params_{ nullptr };

    void generate_leaf_precursor(
      Lowmc_state_words64_ptr leaf_precursor, Mt_index_type leaf_index);
    void generate_leaf_address(uint8_t *leaf_address, Mt_index_type leaf_index);
};


bool check_base_authpath(Lowmc_state_words64_const_ptr root,
  Base_authpath const &path, paramset_t *params) noexcept;

#endif
