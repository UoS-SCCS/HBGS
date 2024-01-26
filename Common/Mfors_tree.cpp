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
#include "Mpc_node_address.h"
#include "Hbgs_lowmc_hash.h"
#include "Mfors_tree.h"

//#define DEBUG_MFORS

uint16_t get_index(uint8_t *bits, uint16_t bit_offset, uint16_t bit_size)
{
    uint8_t index[2];
    uint16_t index_16{ 0 };
    for (uint16_t b = 0; b < bit_size; ++b) {
        setBit(index, b, getBit(bits, static_cast<uint32_t>(bit_offset + b)));
    }
    mem_to_uint<uint16_t>(
      index_16, index, 2, !Public_parameters::use_big_endian_);

    auto div = static_cast<uint16_t>(std::pow(2, 16 - bit_size));
    index_16 /= div;

    return index_16;
}

void signing_indices_from_hash2(Signing_indices &si, H2_data64 const &h2d)
{
    static_assert(
      Public_parameters::d_ <= 16, "signing_indices_from_hash2 assumes d<=16");
    uint16_t bit_size = Public_parameters::d_;
    auto indices_per_state =
      static_cast<uint16_t>(Mpc_parameters::lowmc_state_bits_ / bit_size);

    uint16_t n_indices = Public_parameters::k_;
    assertm(indices_per_state * h2d.size() > n_indices,
      "signing_indices_from_hash2: inconsistent parameters");

    uint8_t state_number{ 0 };
    uint8_t *h2_ptr = (uint8_t *)h2d[state_number++];
    uint16_t bit_offset{ 0 };

    uint16_t index_number{ 0 };
    uint16_t index_16{ 0 };
    while (index_number < n_indices) {
        index_16 = get_index(h2_ptr, bit_offset, bit_size);
        // std::cout << std::dec << index_number << '\t' << std::hex << index_16
        //          << '\n';
        si[index_number++] = index_16;
        bit_offset = static_cast<uint16_t>(bit_offset + bit_size);
        if (bit_offset >= indices_per_state * bit_size) {
            h2_ptr = (uint8_t *)h2d[state_number++];
            bit_offset = 0;
        }
    }
}

void print_signing_indices(std::ostream &os, Signing_indices_const_ptr si)
{
    const size_t print_row_count = 9;
    size_t ctr{ 0 };
    while (ctr < Public_parameters::k_) {
        for (size_t i = 0; i < print_row_count; ++i) {
            if (ctr == Public_parameters::k_) { break; }
            os << si[ctr]
               << ((i == print_row_count - 1
                     || ctr == Public_parameters::k_ - 1)
                      ? '\n'
                      : '\t');
            ctr++;
        }
    }
}

bool read_signing_indices(std::ifstream &is, Signing_indices_ptr si)
{
    for (size_t i = 0; i < Public_parameters::k_; ++i) { is >> si[i]; }
    // !!!! We need some checking here
    return true;
}

Top_path_state top_path_state(uint32_t n_row_nodes, Mt_index_type mt_index)
{
    if (mt_index < n_row_nodes - 1) { return Top_path_state::normal; }
    assertm(mt_index == n_row_nodes - 1,
      "top_path_state: invalid value for mt_index");
    if (mt_index % 2 == 1) { return Top_path_state::hash; }

    return Top_path_state::lift;
}

std::string top_path_state_string(Top_path_state st)
{
    if (st == Top_path_state::normal) { return std::string("normal"); }

    if (st == Top_path_state::hash) { return std::string("hash"); }

    return std::string("lift");
}

void copy_top_authpath(Top_authpath &dest, Top_authpath const &srce)
{
    dest.gt_addr_ = srce.gt_addr_;
    dest.base_tree_no_ = srce.base_tree_no_;
    dest.path_size_ = srce.path_size_;
    std::memcpy(dest.base_tree_root_, srce.base_tree_root_,
      Mpc_parameters::lowmc_state_bytes_);
    for (size_t i = 0; i < srce.path_size_; ++i) {
        std::memcpy(dest.top_path_[i], srce.top_path_[i],
          Mpc_parameters::lowmc_state_bytes_);
    }
}

void copy_mfors_authpath(Mfors_authpath &dest, Mfors_authpath const &srce)
{
    copy_base_authpath(dest.base_path_, srce.base_path_);
    copy_top_authpath(dest.top_path_, srce.top_path_);
}

void calculate_tree_seed(Lowmc_state_words64_ptr tree_seed,
  Lowmc_state_words64_const_ptr master_seed, G_tree_address const &gt_addr,
  paramset_t *params)
{
    constexpr static size_t mf_address_size = gt_row_bytes + gt_index_bytes;
    uint8_t mf_address[mf_address_size];
    uint8_t *next_address = mf_address;
    *next_address = gt_addr.row_;
    next_address += gt_row_bytes;
    uint_to_mem(next_address, gt_index_bytes, gt_addr.index_,
      Public_parameters::use_big_endian_);
    Hash_data hd{ mf_address_size, mf_address };

    lowmc_state_from_hash((uint8_t *)tree_seed, params, master_seed, hd);
}

Mfors_tree::Mfors_tree(Lowmc_state_words64_const_ptr master_seed,
  G_tree_address const &gt_addr, paramset_t *params) noexcept
  : gt_addr_{ gt_addr }, params_(params)
{
    calculate_tree_seed(seed_, master_seed, gt_addr, params);

    assign_row_data();

    status_ = initialised;

#ifdef DEBUG_MFORS
    std::cout << "  Mfors_seed: ";
    print_lowmc_state_words64(std::cout, seed_);
    std::cout << "\nMerkle trees: " << k_ << '\n';
    std::cout << "      Height: " << 0 + height_ << '\n';
#endif
}

void Mfors_tree::assign_row_data() noexcept
{
#ifdef DEBUG_MFORS
    std::cout << "Assigning row data\n";
#endif
    uint32_t n_r = k_;
    size_t first_index = n_tree_nodes_ - n_r;
    size_t row = height_;
    while (row > 0) {
        row_lengths_[row] = n_r;
        row_start_indices_[row] = first_index;
        n_r = (n_r % 2 == 0) ? n_r / 2 : (n_r + 1) / 2;
        first_index -= n_r;
        --row;
    }
    row_start_indices_[0] = first_index;
    row_lengths_[0] = 1;
    assertm(
      first_index == 0, "Mfors_tree: Error calculating the row start indices");
}

bool Mfors_tree::calculate_leaves(Signing_indices_const_ptr indices) noexcept
{
    if (status_ != initialised) { return false; }

    if (status_ == leaves_set) { return true; }

    generate_authpaths_ = (indices != nullptr);

    for (size_t t = 0; t < Public_parameters::k_; ++t) {
        Merkle_tree base_tree(
          seed_, gt_addr_, static_cast<Mt_tree_type>(t), params_);

        Lowmc_state_words64 &current_leaf =
          tree_data_[row_start_indices_[height_] + t];

        base_tree.get_root(current_leaf);
#ifdef DEBUG_MFORS
        if (height_ < 5) {
            std::cout << "\n     Leaf: " << t << '\t' << 0 + height_ << '\t';
            print_lowmc_state_bytes(std::cout, (uint8_t *)current_leaf);
        }
#endif
        if (generate_authpaths_) {
            base_tree.get_authpath(indices[t], authpaths_[t].base_path_);
        }
    }
#ifdef DEBUG_MFORS
    if (height_ < 5) { std::cout << '\n'; }
#endif
    status_ = leaves_set;

    return true;
}

bool Mfors_tree::calculate_nodes() noexcept
{
    if (status_ == nodes_set) { return true; }

    if (status_ != leaves_set) { return false; }

    M_tree_address mt_addr{ k_, 0, 0 };
    Node_address_state node_addr{};
    size_t left_child_index{ 0 };
    size_t right_child_index{ 0 };
    size_t row_start_index{ 0 };
    size_t n_row_nodes{ k_ };
    size_t child_row_start_index = row_start_indices_[height_];
    bool n_child_row_odd{};
    for (uint8_t row = height_ - 1; row < height_; row--) {
        mt_addr.row_ = row;
        n_row_nodes = row_lengths_[row];
        row_start_index = row_start_indices_[row];
        for (size_t row_index = 0; row_index < n_row_nodes - 1; ++row_index) {
            left_child_index = child_row_start_index + 2U * row_index;
            right_child_index = left_child_index + 1U;
            mt_addr.index_ = static_cast<Mt_index_type>(row_index);
            node_addr.set_initial_node_address(gt_addr_, mt_addr);
            hash1b64(tree_data_[row_start_index + row_index],
              tree_data_[left_child_index],
              tree_data_[right_child_index],
              node_addr.node_state64(),
              params_);
#ifdef DEBUG_MFORS
            if (height_ < 5) {
                std::cout << "\n     Node: " << 0 + mt_addr.row_ << '\t'
                          << mt_addr.index_ << '\t';
                print_lowmc_state_bytes(std::cout,
                  (uint8_t *)tree_data_[row_start_index + row_index]);
            }
#endif
        }

        n_child_row_odd = row_lengths_[row + 1U] % 2 != 0;
        left_child_index = child_row_start_index + 2U * (n_row_nodes - 1);
        mt_addr.index_ = static_cast<Mt_index_type>(n_row_nodes - 1);
        if (n_child_row_odd) {// lift
            std::memcpy(tree_data_[row_start_index + n_row_nodes - 1],
              tree_data_[left_child_index],
              Mpc_parameters::lowmc_state_bytes_);
        } else {
            right_child_index = left_child_index + 1U;
            node_addr.set_initial_node_address(gt_addr_, mt_addr);
            hash1b64(tree_data_[row_start_index + n_row_nodes - 1],
              tree_data_[left_child_index],
              tree_data_[right_child_index],
              node_addr.node_state64(),
              params_);
        }
#ifdef DEBUG_MFORS
        if (height_ < 5) {
            std::cout << (n_child_row_odd ? red : blue);
            std::cout << "\n     Node: " << 0 + mt_addr.row_ << '\t'
                      << mt_addr.index_ << '\t';
            print_lowmc_state_bytes(std::cout,
              (uint8_t *)tree_data_[row_start_index + n_row_nodes - 1]);
            std::cout << normal;
        }
#endif
        child_row_start_index = row_start_index;
    }
    status_ = nodes_set;
#ifdef DEBUG_MFORS
    if (height_ < 5) { std::cout << '\n'; }
#endif
    return true;
}

bool Mfors_tree::get_root(Lowmc_state_words64_ptr root) const noexcept
{
    if (status_ != nodes_set) { return false; }

    memcpy(root, tree_data_[0], Mpc_parameters::lowmc_state_bytes_);

    return true;
}

bool Mfors_tree::calculate_top_authpaths() noexcept
{
    if (status_ == paths_set) { return true; }

    if (status_ != nodes_set) {
        std::cerr << "Mfors_tree::calculate_top_authpaths: top nodes not set\n";
        return false;
    }

    if (!generate_authpaths_) {
        std::cerr << "Mfors_tree::calculate_top_authpaths: base authpaths not "
                     "calculated\n";
        return false;
    }

    for (Mt_tree_type bt = 0; bt < Public_parameters::k_; ++bt) {
        if (!get_top_authpath(bt)) {
            std::cerr << "Failed to obtain the top authpath for base tree "
                      << bt << '\n';
            return false;
        }
    }

    status_ = paths_set;

    return true;
}

Mfors_authpath_const_ptr Mfors_tree::get_authpaths() const noexcept
{
    if (status_ != paths_set) { return nullptr; }

    return authpaths_;
}


bool Mfors_tree ::get_top_authpath(Mt_tree_type base_tree_no) noexcept
{
    if (status_ != nodes_set) { return false; }

    if (base_tree_no > k_ - 1) {
        std::cerr << "Mfors_tree::get_top_authpath: given tree_no too large\n";
        return false;
    }

    Top_authpath &path = authpaths_[base_tree_no].top_path_;

    path.gt_addr_ = gt_addr_;
    path.base_tree_no_ = base_tree_no;

    size_t path_index{ 0 };
    Mt_index_type row_index{ base_tree_no };
    uint32_t n_row_nodes = k_;
    size_t row{ height_ };
    std::memcpy(path.base_tree_root_,
      tree_data_[row_start_indices_[row] + base_tree_no],
      Mpc_parameters::lowmc_state_bytes_);
#ifdef DEBUG_MFORS
    if (height_ < 5 && path_index == 0) {
        std::cout << "\n     Leaf: " << 0 + base_tree_no << '\t' << 0 + row
                  << '\t' << row_index << '\t' << path_index << '\t';
        print_lowmc_state_bytes(std::cout, (uint8_t *)path.base_tree_root_);
    }
#endif
    Top_path_state path_state;
    Index_parity row_index_parity;
    for (uint8_t i = 0; i < height_; ++i) {
        path_state = top_path_state(n_row_nodes, row_index);
        row_index_parity =
          (row_index % 2 == 0) ? Index_parity::even : Index_parity::odd;
        if (path_state == Top_path_state::normal) {
            if (row_index_parity == Index_parity::even) {
                std::memcpy(path.top_path_[path_index++],
                  tree_data_[row_start_indices_[row] + row_index + 1],
                  Mpc_parameters::lowmc_state_bytes_);
            } else {
                std::memcpy(path.top_path_[path_index++],
                  tree_data_[row_start_indices_[row] + row_index - 1],
                  Mpc_parameters::lowmc_state_bytes_);
            }
        } else if (path_state == Top_path_state::hash) {
            std::memcpy(path.top_path_[path_index++],
              tree_data_[row_start_indices_[row] + row_index - 1],
              Mpc_parameters::lowmc_state_bytes_);
        }
#ifdef DEBUG_MFORS
        if (height_ < 5 && path_index > 0) {
            std::cout << "\n     Hash: " << 0 + base_tree_no << '\t' << 0 + row
                      << '\t' << row_index << '\t' << path_index - 1 << '\t';
            print_lowmc_state_bytes(
              std::cout, (uint8_t *)path.top_path_[path_index - 1]);
            std::cout << '\t' << 0 + i;
        }
#endif
        n_row_nodes = n_parent_row_nodes(n_row_nodes);
        row_index /= 2;
        row--;
    }
    path.path_size_ = path_index;
#ifdef DEBUG_MFORS
    if (height_ < 5) {
        std::cout << "\nPath size: " << path.path_size_ << '\n';
    }
#endif

    return true;
}

bool check_top_authpath(Lowmc_state_words64_const_ptr root,
  Top_authpath const &path, paramset_t *params) noexcept
{
    Node_address_state node_addr{};
    G_tree_address gt_addr = path.gt_addr_;
    M_tree_address mt_addr = { path.m_tree_, Top_authpath::height_,
        path.base_tree_no_ };

    Lowmc_state_words64 tree_hash{ 0 };
    std::memcpy(
      tree_hash, path.base_tree_root_, Mpc_parameters::lowmc_state_bytes_);

    node_addr.set_initial_node_address(gt_addr, mt_addr);
    uint32_t n_row_nodes = Public_parameters::k_;
    uint8_t path_index{ 0 };

#ifdef DEBUG_MFORS
    if (Top_authpath::height_ < 5) {
        std::cout << "\n     Top root: " << Top_authpath::height_ + 0 << '\t'
                  << path.base_tree_no_ << '\t' << 0 + path_index << '\t';
        print_lowmc_state_bytes(std::cout, (uint8_t *)root);
        std::cout << "\n         Leaf: " << Top_authpath::height_ + 0 << '\t'
                  << path.base_tree_no_ << '\t' << 0 + path_index << '\t';
        print_lowmc_state_bytes(std::cout, (uint8_t *)tree_hash);
    }
#endif

    Mt_index_type child_row_index{ 0 };
    Index_parity child_row_index_parity;
    Top_path_state path_state;
    for (uint8_t row = Top_authpath::height_; row > 0; --row) {

        if (path_index == path.path_size_) {
            std::cerr << "Error calculating the path, path index exceeded\n";
            return false;
        }

        child_row_index = node_addr.get_mt_index();
        child_row_index_parity = node_addr.lsb_parity();
        node_addr.update_mt_row_and_index();// Set for the new parent hash
        path_state = top_path_state(n_row_nodes, child_row_index);

        if (path_state == Top_path_state::normal) {// Just do the hash
            tree_path_hash(tree_hash, path.top_path_[path_index++],
              child_row_index_parity, node_addr, params);
        } else if (path_state == Top_path_state::hash) {
            hash1b64(tree_hash, path.top_path_[path_index++], tree_hash,
              node_addr.node_state64(), params);
        }
#ifdef DEBUG_MFORS
        if (Top_authpath::height_ < 5) {
            std::cout << "\n   Path state: "
                      << top_path_state_string(
                           top_path_state(n_row_nodes, child_row_index));
            std::cout << "\nNew node addr: " << row + 0 << '\t'
                      << child_row_index << '\t' << 0 + path_index - 1 << '\t';
            print_lowmc_state_bytes(
              std::cout, (uint8_t *)node_addr.node_state());
            std::cout << "\n         Hash: " << row + 0 << '\t'
                      << child_row_index << '\t' << 0 + path_index - 1 << '\t';
            print_lowmc_state_bytes(std::cout, (uint8_t *)tree_hash);
        }
#endif
        n_row_nodes = n_parent_row_nodes(n_row_nodes);
    }
#ifdef DEBUG_MFORS
    if (Top_authpath::height_ < 5) { std::cout << '\n'; }
#endif
    if (path_index != path.path_size_) {
        std::cerr << "Inconsistent path size\n";
        return false;
    }
    if (std::memcmp(root, tree_hash, Mpc_parameters::lowmc_state_bytes_) != 0) {
        return false;
    }

    return true;
}

bool check_mfors_authpaths(Lowmc_state_words64_const_ptr root,
  Mfors_authpath_const_ptr paths, paramset_t *params)
{
    for (Mt_tree_type t = 0; t < Public_parameters::k_; ++t) {
        Base_authpath const &bp = paths[t].base_path_;
        Top_authpath const &tp = paths[t].top_path_;

        assertm(t == paths[t].top_path_.base_tree_no_,
          "Inconsistent path and base tree number");

        if (!check_base_authpath(tp.base_tree_root_, bp, params)) {
            std::cerr << "check_authpaths: check_base_authpath failed for tree "
                      << 0 + t << '\n';

            std::cout << "Root: ";
            print_lowmc_state_words64(std::cout, tp.base_tree_root_);
            std::cout << '\n';
            return false;
        }
#ifdef DEBUG_MFORS
        if (Top_authpath::height_ < 5) {
            std::cout << "\n Base for tree " << 0 + t << " checked OK";
        }
#endif

        if (!check_top_authpath(root, tp, params)) {
            std::cerr << "check_authpaths: check_top_authpath failed for tree "
                      << 0 + t << '\n';
            return false;
        }
    }

    return true;
}

void print_mfors_authpaths(std::ostream &os, Mfors_authpath_const_ptr paths)
{
    for (Mt_tree_type t = 0; t < Public_parameters::k_; ++t) {
#ifdef DEBUG_MFORS
        std::cout << "Wrting data for tree " << 0 + t << '\n';
#endif
        Base_authpath const &bp = paths[t].base_path_;
        Top_authpath const &tp = paths[t].top_path_;
#ifdef DEBUG_MFORS
        std::cout << "Base path for: " << 0 + bp.gt_addr_.row_ << '\t'
                  << bp.gt_addr_.index_ << '\t' << 0 + bp.m_tree_ << '\t'
                  << bp.leaf_index_ << '\n';
#endif
        os << 0 + bp.gt_addr_.row_ << '\t' << bp.gt_addr_.index_ << '\t'
           << 0 + bp.m_tree_ << '\t' << bp.leaf_index_ << '\n';
        print_lowmc_state_bytes(os, (uint8_t *)bp.leaf_precursor_);
        os << '\n' << 0 + bp.depth_ << '\n';
        for (size_t i = 0; i < 0 + bp.depth_; ++i) {
            print_lowmc_state_bytes(os, (uint8_t *)bp.path_[i]);
            os << '\n';
        }
#ifdef DEBUG_MFORS
        std::cout << "Top path for: " << 0 + tp.gt_addr_.row_ << '\t'
                  << tp.gt_addr_.index_ << '\t' << 0 + tp.m_tree_ << '\t'
                  << tp.base_tree_no_ << '\t';
        std::cout << "size: " << tp.path_size_ << '\n';
#endif
        os << 0 + tp.gt_addr_.row_ << '\t' << tp.gt_addr_.index_ << '\t'
           << 0 + tp.m_tree_ << '\t' << tp.base_tree_no_ << '\n';
        os << tp.path_size_ << '\n';
        print_lowmc_state_bytes(os, (uint8_t *)tp.base_tree_root_);
        os << '\n';

        for (size_t i = 0; i < tp.path_size_; ++i) {
            print_lowmc_state_bytes(os, (uint8_t *)tp.top_path_[i]);
            os << '\n';
        }
        os << std::endl;
    }
}

bool read_mfors_authpaths(std::ifstream &is, Mfors_authpath_ptr paths)
{
    bool read_ok{ true };
    std::string tmp;
    [[maybe_unused]] Mt_tree_type pn;
    uint16_t uint8_tmp;
    is >> std::ws;
    for (Mt_tree_type t = 0; t < Public_parameters::k_; ++t) {
        Base_authpath &bp = paths[t].base_path_;
        Top_authpath &tp = paths[t].top_path_;
        is >> uint8_tmp;
        bp.gt_addr_.row_ = static_cast<uint8_t>(uint8_tmp);
        is >> bp.gt_addr_.index_;
        is >> uint8_tmp;
        bp.m_tree_ = static_cast<uint8_t>(uint8_tmp);
        is >> bp.leaf_index_;
#ifdef DEBUG_MFORS
        std::cout << "g row=" << 0 + bp.gt_addr_.row_
                  << " g index=" << bp.gt_addr_.index_
                  << " m tree=" << 0 + bp.m_tree_
                  << " leaf index=" << bp.leaf_index_ << '\n';
        ;
        std::cout << "reading leaf precursor\n";
#endif
        if (!read_lowmc_state_bytes(is, (uint8_t *)bp.leaf_precursor_)) {
            std::cerr << "read_lowmc_state_bytes failed\n";
            return false;
        }

        is >> uint8_tmp;
#ifdef DEBUG_MFORS
        std::cout << "reading depth=" << uint8_tmp << std::endl;
#endif
        assertm(
          uint8_tmp == bp.depth_, "Inconsistent depth value read from file");
        for (size_t i = 0; i < 0 + bp.depth_; ++i) {
#ifdef DEBUG_MFORS
            std::cout << "reading base path " << i << '\n';
#endif
            if (!read_lowmc_state_bytes(is, (uint8_t *)bp.path_[i])) {
                std::cerr << "read_lowmc_state_bytes failed\n";
                return false;
            }
        }
        is >> uint8_tmp;
        tp.gt_addr_.row_ = static_cast<uint8_t>(uint8_tmp);
        is >> tp.gt_addr_.index_;
        is >> uint8_tmp;
        if (uint8_tmp != tp.m_tree_) {
            std::cerr
              << "Inconsitent value read for the top tree number (must be "
              << Public_parameters::k_ << ")\n";
            return EXIT_FAILURE;
        }
        is >> uint8_tmp;
        tp.base_tree_no_ = static_cast<uint8_t>(uint8_tmp);
        is >> tp.path_size_;
        if (!read_lowmc_state_bytes(is, (uint8_t *)tp.base_tree_root_)) {
            std::cerr << "read_lowmc_state_bytes failed\n";
            return false;
        }
        for (size_t i = 0; i < tp.path_size_; ++i) {
#ifdef DEBUG_MFORS
            std::cout << "reading top path " << i << '\n';
#endif
            if (!read_lowmc_state_bytes(is, (uint8_t *)tp.top_path_[i])) {
                std::cerr << "read_lowmc_state_bytes failed\n";
                return false;
            }
        }
#ifdef DEBUG_MFORS
        std::cout << "authpath for Merkle tree t=" << 0 + t << " read OK\n";
#endif
    }

    return read_ok;
}
