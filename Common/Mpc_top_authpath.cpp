/*******************************************************************************
 * File:        Mpc_top_authpath.cpp
 * Description: MPC code for a top authpath
 *
 * Author:      Chris Newton
 * Created:     Thursday 2 June 2022
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
#include <cassert>
#include "Io_utils.h"
#include "Clock_utils.h"

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
}

#include "Hbgs_param.h"
#include "Picnic_mpc_functions.h"
#include "Mpc_utils.h"
#include "Mpc_lowmc64.h"
#include "Mpc_hash1.h"
#include "Mpc_parameters.h"
#include "Mpc_signature_utils.h"
#include "Mpc_working_data.h"
#include "Mpc_sign.h"
#include "Mpc_verify.h"
#include "Mpc_node_address.h"
#include "Mfors_tree.h"
#include "Mpc_top_authpath.h"

//#define DEBUG_TOP_MPC

Mpc_top_authpath::Mpc_top_authpath(
  Top_authpath const &top_authpath, Mpc_proof_indices const &indices) noexcept
{
    copy_top_authpath(top_path_, top_authpath);
    M_tree_address mta{ top_authpath.m_tree_, height_,
        top_authpath.base_tree_no_ };
    initial_node_addr_.set_initial_node_address(top_authpath.gt_addr_, mta);

    base_input_index_ = indices.input_index_;
    base_mpc_index_ = indices.mpc_input_index_;
    base_output_index_ = indices.output_index_;

    get_param_set(get_picnic_parameter_set_id(), &paramset_);
}

Tape_offset Mpc_top_authpath::set_offsets(Tape_offset const &of) noexcept
{
    base_offset_ = of;

    base_offset_ = initial_node_addr_.set_offsets(base_offset_);

    for (auto &os : path_offsets_) {
        os = base_offset_;
        base_offset_ += Mpc_parameters::lowmc_state_bits_;
    }

    for (auto &os : intermediate_offsets_) {
        os = base_offset_;
        base_offset_ += Mpc_parameters::lowmc_state_bits_;
    }

    // Check for consistency, Node_address_state doesn't use all the bits here
    assertm(base_offset_ == of + local_offset_bits_ - mt_index_bits,
      "Inconsistent offset values");

    return of + tape_bits_ + offset_bits_;
}

void Mpc_top_authpath::compute_aux_tape_sign(randomTape_t *tapes,
  Mpc_working_data &mpc_wd, Lowmc_state_words64_const_ptr base_tree_root_mask,
  Lowmc_state_words64_const_ptr mfors_tree_root_mask, size_t t) noexcept
{
#ifdef DEBUG_TOP_MPC
    if (t == 0) {
        std::cout << "Top authpath: node address:\n";
        initial_node_addr_.put_node_data(std::cout);
        std::cout << "Path size: " << top_path_.path_size_
                  << "\n     Base tree root: ";
        print_lowmc_state_bytes(
          std::cout, (uint8_t *)top_path_.base_tree_root_);
        std::cout << "\nMfors_tree_root_mask: ";
        print_lowmc_state_bytes(std::cout, (uint8_t *)mfors_tree_root_mask);
        std::cout << "\nPath:\n";
        for (size_t i = 0; i < top_path_.path_size_; ++i) {
            print_lowmc_state_bytes(
              std::cout, (uint8_t *)top_path_.top_path_[i]);
            std::cout << "\n";
        }
    }
#endif

    randomTape_t *current_tape_ptr = &tapes[t];

    Node_address_state node_addr{ initial_node_addr_ };

    Lowmc_state_words64 current_hash_mask{ 0 };
    std::memcpy(current_hash_mask, base_tree_root_mask,
      Mpc_parameters::lowmc_state_bytes_);

    node_addr.set_and_apply_initial_mask(tapes, t);

    uint32_t n_row_nodes = Public_parameters::k_;
    uint32_t n_child_row_nodes{ 0 };
    uint8_t path_index{ 0 };
    Mt_index_type child_row_index{ 0 };
    Index_parity child_row_index_parity;
    Top_path_state path_state;
    Tape_offset next_offset{ base_offset_ };
    Lowmc_state_words64 authpath_mask{ 0 };
    Lowmc_state_words64 next_hash_mask{ 0 };

    for (Mt_row_type i = 0; i < Top_authpath::height_; ++i) {
        n_child_row_nodes = n_row_nodes;
        n_row_nodes = n_parent_row_nodes(n_row_nodes);

        child_row_index = node_addr.get_mt_index();
        child_row_index_parity = node_addr.lsb_parity();
        path_state = top_path_state(n_child_row_nodes, child_row_index);

        node_addr.update_mt_row_and_index();// Set for the new hash

#ifdef DEBUG_TOP_MPC
        if (Top_authpath::height_ < 5 && t == 0) {
            std::cout << "\n       Path state: "
                      << top_path_state_string(path_state);
            std::cout << "\n        Node addr: ";
            print_lowmc_state_bytes(
              std::cout, (uint8_t *)node_addr.node_state());
        }
#endif
        if (path_state == Top_path_state::lift) {
#ifdef DEBUG_TOP_MPC
            if (Top_authpath::height_ < 5 && t == 0) {
                std::cout << red << "hash lifted\n" << normal;
            }
#endif
            continue;
        }

        get_mask_from_tapes(authpath_mask, current_tape_ptr,
          path_offsets_[path_index], &paramset_);

        if (i < Top_authpath::height_ - 1) {
            get_mask_from_tapes(next_hash_mask, current_tape_ptr,
              intermediate_offsets_[path_index], &paramset_);
        } else {
            if (mfors_tree_root_mask != nullptr) {
                std::memcpy(next_hash_mask, mfors_tree_root_mask,
                  Mpc_parameters::lowmc_state_bytes_);
            } else {
                std::memset(
                  next_hash_mask, 0, Mpc_parameters::lowmc_state_bytes_);
            }
        }

#ifdef DEBUG_TOP_MPC
        if (Top_authpath::height_ < 5 && t == 0) {
            std::cout << "\nCurrent hash mask: ";
            print_lowmc_state_bytes(std::cout, (uint8_t *)current_hash_mask);
            std::cout << "\n   Next hash mask: ";
            print_lowmc_state_bytes(std::cout, (uint8_t *)next_hash_mask);
            std::cout << '\n';
        }
#endif
        size_t mpc_index_base = base_mpc_index_ + 2U * path_index;
        auto first_mask_adjustment =
          (Word *)mpc_wd.mpc_inputs_[mpc_index_base][t];
        auto intermediate_mask_adjustment =
          (Word *)mpc_wd.mpc_inputs_[mpc_index_base + 1][t];

        if (path_state == Top_path_state::normal) {
            Unmasked_tree_hash unmasked_tree_hash;
            next_offset = unmasked_tree_hash.set_offsets(next_offset);

            unmasked_tree_hash.compute_aux_tape(current_tape_ptr,
              current_hash_mask, authpath_mask, child_row_index_parity,
              node_addr, next_hash_mask, first_mask_adjustment,
              intermediate_mask_adjustment, &paramset_);
#ifdef DEBUG_TOP_MPC
            if (Top_authpath::height_ < 5 && t == 0) {
                std::cout << red << "unmasked_tree_hash masks evaluated:\n"
                          << normal << "i: " << i
                          << ", path index: " << 0 + path_index
                          << ", mpc_indices: " << mpc_index_base << " and "
                          << mpc_index_base + 1 << '\n';
            }
#endif
        } else {
            Hash1b hash1b;
            next_offset = hash1b.set_offsets(next_offset);

            hash1b.compute_aux_tape(current_tape_ptr, authpath_mask,
              current_hash_mask, node_addr.node_mask64(), next_hash_mask,
              first_mask_adjustment, intermediate_mask_adjustment, &paramset_);
#ifdef DEBUG_TOP_MPC
            if (Top_authpath::height_ < 5 && t == 0) {
                std::cout << red << "hash1b masks evaluated:\n"
                          << normal << "i: " << i
                          << ", path index: " << 0 + path_index
                          << ", mpc_indices: " << mpc_index_base << " and "
                          << mpc_index_base + 1 << '\n';
            }
#endif
        }

        path_index++;
        std::memcpy(current_hash_mask, next_hash_mask,
          Mpc_parameters::lowmc_state_bytes_);
    }

#ifdef DEBUG_TOP_MPC
    if (t == 0) {
        std::cout << blue
                  << "\n============ compute_aux_sign completed ============\n"
                  << normal;
    }
#endif
}

// !!!! Just duplicate for now - there must be a better way!
void Mpc_top_authpath::compute_aux_tape_verify(randomTape_t *tapes,
  [[maybe_unused]] Signature_data const &sig_data,
  Lowmc_state_words64_const_ptr base_tree_root_mask,
  Lowmc_state_words64_const_ptr mfors_tree_root_mask, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

    Node_address_state node_addr{ initial_node_addr_ };

    Lowmc_state_words64 current_hash_mask{ 0 };
    std::memcpy(current_hash_mask, base_tree_root_mask,
      Mpc_parameters::lowmc_state_bytes_);

    node_addr.set_and_apply_initial_mask(tapes, t);

    uint32_t n_row_nodes = Public_parameters::k_;
    uint32_t n_child_row_nodes{ 0 };
    uint8_t path_index{ 0 };
    Mt_index_type child_row_index{ 0 };
    Index_parity child_row_index_parity;
    Top_path_state path_state;
    Tape_offset next_offset{ base_offset_ };
    Lowmc_state_words64 authpath_mask{ 0 };
    Lowmc_state_words64 next_hash_mask{ 0 };

    for (Mt_row_type i = 0; i < Top_authpath::height_; ++i) {
        n_child_row_nodes = n_row_nodes;
        n_row_nodes = n_parent_row_nodes(n_row_nodes);

        child_row_index = node_addr.get_mt_index();
        child_row_index_parity = node_addr.lsb_parity();
        path_state = top_path_state(n_child_row_nodes, child_row_index);

        node_addr.update_mt_row_and_index();// Set for the new hash

        if (path_state == Top_path_state::lift) { continue; }

        get_mask_from_tapes(authpath_mask, current_tape_ptr,
          path_offsets_[path_index], &paramset_);

        if (i < Top_authpath::height_ - 1) {
            get_mask_from_tapes(next_hash_mask, current_tape_ptr,
              intermediate_offsets_[path_index], &paramset_);
        } else {
            if (mfors_tree_root_mask != nullptr) {
                std::memcpy(next_hash_mask, mfors_tree_root_mask,
                  Mpc_parameters::lowmc_state_bytes_);
            } else {
                std::memset(
                  next_hash_mask, 0, Mpc_parameters::lowmc_state_bytes_);
            }
        }

        Word *first_mask_adjustment = nullptr;
        Word *intermediate_mask_adjustment = nullptr;

        if (path_state == Top_path_state::normal) {
            Unmasked_tree_hash unmasked_tree_hash;
            next_offset = unmasked_tree_hash.set_offsets(next_offset);

            unmasked_tree_hash.compute_aux_tape(current_tape_ptr,
              current_hash_mask, authpath_mask, child_row_index_parity,
              node_addr, next_hash_mask, first_mask_adjustment,
              intermediate_mask_adjustment, &paramset_);
        } else {
            Hash1b hash1b;
            next_offset = hash1b.set_offsets(next_offset);

            hash1b.compute_aux_tape(current_tape_ptr, authpath_mask,
              current_hash_mask, node_addr.node_mask64(), next_hash_mask,
              first_mask_adjustment, intermediate_mask_adjustment, &paramset_);
        }

        path_index++;
        std::memcpy(current_hash_mask, next_hash_mask,
          Mpc_parameters::lowmc_state_bytes_);
    }
}

void Mpc_top_authpath::get_aux_bits(uint8_t *aux_bits, Tape_offset &aux_pos,
  randomTape_t *tapes, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

    Node_address_state node_addr{ initial_node_addr_ };

    uint32_t n_row_nodes = Public_parameters::k_;
    uint32_t n_child_row_nodes{ 0 };
    Mt_index_type child_row_index{ 0 };
    Top_path_state path_state;
    Tape_offset next_offset{ base_offset_ };

    for (Mt_row_type i = 0; i < Top_authpath::height_; ++i) {
        n_child_row_nodes = n_row_nodes;
        n_row_nodes = n_parent_row_nodes(n_row_nodes);

        child_row_index = node_addr.get_mt_index();
        path_state = top_path_state(n_child_row_nodes, child_row_index);

        node_addr.update_mt_row_and_index();// Set for the new hash

        if (path_state == Top_path_state::lift) { continue; }

        if (path_state == Top_path_state::normal) {
            Unmasked_tree_hash unmasked_tree_hash;
            next_offset = unmasked_tree_hash.set_offsets(next_offset);

            unmasked_tree_hash.get_aux_bits(
              aux_bits, aux_pos, current_tape_ptr);

        } else {
            Hash1b hash1b;
            next_offset = hash1b.set_offsets(next_offset);

            hash1b.get_aux_bits(aux_bits, aux_pos, current_tape_ptr);
        }
    }
}

void Mpc_top_authpath::set_aux_bits(randomTape_t *tapes, Tape_offset &aux_pos,
  Signature_data const &sig_data, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

    Node_address_state node_addr{ initial_node_addr_ };

    uint32_t n_row_nodes = Public_parameters::k_;
    uint32_t n_child_row_nodes{ 0 };
    Mt_index_type child_row_index{ 0 };
    Top_path_state path_state;
    Tape_offset next_offset{ base_offset_ };

    for (Mt_row_type i = 0; i < Top_authpath::height_; ++i) {
        n_child_row_nodes = n_row_nodes;
        n_row_nodes = n_parent_row_nodes(n_row_nodes);

        child_row_index = node_addr.get_mt_index();
        path_state = top_path_state(n_child_row_nodes, child_row_index);

        node_addr.update_mt_row_and_index();// Set for the new hash

        if (path_state == Top_path_state::lift) { continue; }

        if (path_state == Top_path_state::normal) {
            Unmasked_tree_hash unmasked_tree_hash;
            next_offset = unmasked_tree_hash.set_offsets(next_offset);

            unmasked_tree_hash.set_aux_bits(
              current_tape_ptr, aux_pos, sig_data.proofs_[t]->aux_);

        } else {
            Hash1b hash1b;
            next_offset = hash1b.set_offsets(next_offset);

            hash1b.set_aux_bits(
              current_tape_ptr, aux_pos, sig_data.proofs_[t]->aux_);
        }
    }
}

int Mpc_top_authpath::mpc_simulate_sign(randomTape_t *tapes,
  Lowmc_state_words64_const_ptr masked_base_tree_root, Mpc_working_data &mpc_wd,
  shares_t *tmp_shares, Lowmc_state_words64_ptr output, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];
    msgs_t *msgs = &mpc_wd.msgs_[t];

    Node_address_state node_addr{ initial_node_addr_ };

    Lowmc_state_words64 current_masked_hash{ 0 };
    std::memcpy(current_masked_hash, masked_base_tree_root,
      Mpc_parameters::lowmc_state_bytes_);

    node_addr.set_and_apply_initial_mask(tapes, t);

#ifdef DEBUG_TOP_MPC
    if (Top_authpath::height_ < 5 && t == 0) {
        std::cout << "\nNode address after initial mask\tt: " << t << '\n';
        node_addr.put_node_data(std::cout);
        std::cout << '\n';
    }
#endif

    uint32_t n_row_nodes = Public_parameters::k_;
    uint32_t n_child_row_nodes{ 0 };
    uint8_t path_index{ 0 };
    Mt_index_type child_row_index{ 0 };
    Index_parity child_row_index_parity;
    Top_path_state path_state;
    Tape_offset next_offset{ base_offset_ };
    Lowmc_state_words64 authpath_mask{ 0 };
    Lowmc_state_words64 masked_auth{ 0 };
    Lowmc_state_words64 next_masked_hash{ 0 };

    int rv{ 0 };
    for (size_t i = 0; i < Top_authpath::height_; ++i) {

        n_child_row_nodes = n_row_nodes;
        n_row_nodes = n_parent_row_nodes(n_row_nodes);

        child_row_index = node_addr.get_mt_index();
        child_row_index_parity = node_addr.lsb_parity();
        path_state = top_path_state(n_child_row_nodes, child_row_index);

        node_addr.update_mt_row_and_index();// Set for the new hash

        if (path_state == Top_path_state::lift) {
#ifdef DEBUG_TOP_MPC
            if (Top_authpath::height_ < 5 && t == 0) {
                std::cout << red << "hash lifted\n" << normal;
            }
#endif
            continue;
        }

        get_mask_from_tapes(authpath_mask, current_tape_ptr,
          path_offsets_[path_index], &paramset_);

        Lowmc_state_words64_const_ptr auth = top_path_.top_path_[path_index];
        xor64(masked_auth, auth, authpath_mask);

        size_t mpc_index_base = base_mpc_index_ + 2U * path_index;
        size_t input_index_base = base_input_index_ + 3U * path_index;

        auto masked_left = (Word *)mpc_wd.inputs_[input_index_base][t];
        auto masked_right = (Word *)mpc_wd.inputs_[input_index_base + 1][t];
        auto masked_node = (Word *)mpc_wd.inputs_[input_index_base + 2][t];

        std::memcpy(masked_node, node_addr.node_state(),
          Mpc_parameters::lowmc_state_bytes_);

#ifdef DEBUG_TOP_MPC
        if (Top_authpath::height_ < 5 && t == 0) {
            std::cout << "\n   Path state: "
                      << top_path_state_string(path_state);
            std::cout << "\nNew node addr:\t";
            print_lowmc_state_bytes(std::cout, (uint8_t *)masked_node);
            std::cout << '\n';
        }
#endif

        auto first_mask_adjustment =
          (Word *)mpc_wd.mpc_inputs_[mpc_index_base][t];
        auto intermediate_mask_adjustment =
          (Word *)mpc_wd.mpc_inputs_[mpc_index_base + 1][t];

        if (path_state == Top_path_state::normal) {

            Unmasked_tree_hash unmasked_tree_hash;
            next_offset = unmasked_tree_hash.set_offsets(next_offset);
            rv = unmasked_tree_hash.mpc_simulate_sign(current_tape_ptr,
              current_masked_hash, masked_auth, child_row_index_parity,
              node_addr, tmp_shares, msgs, first_mask_adjustment,
              intermediate_mask_adjustment, masked_left, masked_right,
              next_masked_hash, &paramset_);
            if (rv != EXIT_SUCCESS) {
                std::cerr << "MPC simulation, unmasked tree hash, for i=" << i
                          << " failed for round " << t
                          << ", signature invalid\n";
                return EXIT_FAILURE;
            }
#ifdef DEBUG_TOP_MPC
            if (Top_authpath::height_ < 5 && t == 0) {
                std::cout << red << "unmasked_tree_hash evaluated\n"
                          << normal << "i: " << i
                          << ", path index: " << 0 + path_index
                          << ", mpc_indices: " << mpc_index_base << " and "
                          << mpc_index_base + 1
                          << ", input_indices: " << input_index_base << ", "
                          << input_index_base + 1 << " and "
                          << input_index_base + 2 << '\n';
            }
#endif
        } else {
            Hash1b hash1b;
            next_offset = hash1b.set_offsets(next_offset);
            // first_mask_adjustment absorbed into masked_left
            xor64(masked_left, masked_auth, first_mask_adjustment);
            std::memcpy(
              masked_right, current_masked_hash, paramset_.stateSizeBytes);

            rv = hash1b.mpc_simulate(masked_left, masked_right, masked_node,
              intermediate_mask_adjustment, current_tape_ptr, tmp_shares, msgs,
              next_masked_hash, &paramset_);
            if (rv != EXIT_SUCCESS) {
                std::cerr << "MPC simulation, Hash1b , for i=" << i
                          << " failed for round " << t
                          << ", signature invalid\n";
                return EXIT_FAILURE;
            }
#ifdef DEBUG_TOP_MPC
            if (Top_authpath::height_ < 5 && t == 0) {
                std::cout << red << "hash1b evaluated\n"
                          << normal << "i: " << i
                          << ", path index: " << 0 + path_index
                          << ", mpc_indices: " << mpc_index_base << " and "
                          << mpc_index_base + 1
                          << ", input_indices: " << input_index_base << ", "
                          << input_index_base + 1 << " and "
                          << input_index_base + 2 << '\n';
            }
#endif
        }

#ifdef DEBUG_TOP_MPC
        if (Top_authpath::height_ < 5 && t == 0) {
            if (path_index < top_path_.path_size_) {
                std::cout << "\nMasked hash for i: " << i
                          << ", path index: " << 0 + path_index << ":\n";
                print_lowmc_state_words64(std::cout, next_masked_hash);
                std::cout << "\n";

                Lowmc_state_words64 next_hash_mask{ 0 };
                get_mask_from_tapes(next_hash_mask, current_tape_ptr,
                  intermediate_offsets_[path_index], &paramset_);

                Lowmc_state_words64 unmasked_hash{ 0 };
                xor64(unmasked_hash, next_masked_hash, next_hash_mask);
                std::cout << "Un-masked hash for i: " << i
                          << ", path index: " << 0 + path_index << ":\n";
                print_lowmc_state_words64(std::cout, unmasked_hash);
                std::cout << "\n\n";
            } else {
                std::cout << "Path limit reached\n\n";
            }
        }
#endif
        path_index++;

        std::memcpy(current_masked_hash, next_masked_hash,
          Mpc_parameters::lowmc_state_bytes_);
    }

    std::memcpy(
      output, current_masked_hash, Mpc_parameters::lowmc_state_bytes_);

#ifdef DEBUG_TOP_MPC
    if (t == 0) {
        std::cout << blue
                  << "\n============ mpc_simulate_sign completed ============\n"
                  << normal;
    }
#endif

    return rv;
}

int Mpc_top_authpath::mpc_simulate_and_verify(randomTape_t *tapes,
  Lowmc_state_words64_const_ptr masked_base_tree_root,
  Signature_data const &sig_data, msgs_t *msgs, Lowmc_state_words64_ptr output,
  shares_t *tmp_shares, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

    Node_address_state node_addr{ initial_node_addr_ };

    Lowmc_state_words64 current_masked_hash{ 0 };
    std::memcpy(current_masked_hash, masked_base_tree_root,
      Mpc_parameters::lowmc_state_bytes_);

    node_addr.set_and_apply_initial_mask(tapes, t);

    uint32_t n_row_nodes = Public_parameters::k_;
    uint32_t n_child_row_nodes{ 0 };
    uint8_t path_index{ 0 };
    Mt_index_type child_row_index{ 0 };
    // Index_parity child_row_index_parity;
    Top_path_state path_state;
    Tape_offset next_offset{ base_offset_ };
    Lowmc_state_words64 next_masked_hash{ 0 };

    int rv{ 0 };
    for (size_t i = 0; i < Top_authpath::height_; ++i) {

        n_child_row_nodes = n_row_nodes;
        n_row_nodes = n_parent_row_nodes(n_row_nodes);

        child_row_index = node_addr.get_mt_index();
        // child_row_index_parity = node_addr.lsb_parity();
        path_state = top_path_state(n_child_row_nodes, child_row_index);

        node_addr.update_mt_row_and_index();// Set for the new hash

        if (path_state == Top_path_state::lift) {
#ifdef DEBUG_TOP_MPC
            if (Top_authpath::height_ < 5 && t == 0) {
                std::cout << red << "hash lifted\n" << normal;
            }
#endif
            continue;
        }

        size_t mpc_index_base = base_mpc_index_ + 2U * path_index;
        size_t input_index_base = base_input_index_ + 3U * path_index;

        auto masked_left =
          (Word *)sig_data.proofs_[t]->inputs_[input_index_base];
        auto masked_right =
          (Word *)sig_data.proofs_[t]->inputs_[input_index_base + 1];

        auto masked_node =
          (Word *)sig_data.proofs_[t]->inputs_[input_index_base + 2];

        auto first_mask_adjustment =
          (Word *)sig_data.proofs_[t]->mpc_inputs_[mpc_index_base];
        auto intermediate_mask_adjustment =
          (Word *)sig_data.proofs_[t]->mpc_inputs_[mpc_index_base + 1];

        if (path_state == Top_path_state::normal) {

            Unmasked_tree_hash unmasked_tree_hash;
            next_offset = unmasked_tree_hash.set_offsets(next_offset);

            rv = unmasked_tree_hash.mpc_simulate_for_verify(current_tape_ptr,
              masked_left, masked_right, masked_node, tmp_shares, msgs,
              first_mask_adjustment, intermediate_mask_adjustment,
              next_masked_hash, &paramset_);
            if (rv != 0) {
                std::cerr << "MPC simulation, masked tree hash, for i=" << i
                          << " failed for round " << t
                          << ", signature invalid\n";
                return EXIT_FAILURE;
            }
        } else {
            Hash1b hash1b;
            next_offset = hash1b.set_offsets(next_offset);
            // first_mask_adjustment was absorbed into masked_left for this case
            rv = hash1b.mpc_simulate(masked_left, masked_right, masked_node,
              intermediate_mask_adjustment, current_tape_ptr, tmp_shares, msgs,
              next_masked_hash, &paramset_);
            if (rv != EXIT_SUCCESS) {
                std::cerr << "MPC simulation, Hash1b , for i=" << i
                          << " failed for round " << t
                          << ", signature invalid\n";
                return EXIT_FAILURE;
            }
        }

        path_index++;
        //            std::memcpy(
        //              current_hash, next_hash,
        //              Mpc_parameters::lowmc_state_bytes_);
    }

    std::memcpy(output, next_masked_hash, Mpc_parameters::lowmc_state_bytes_);

    if (Top_authpath::height_ < 5 && t == 0) {
        std::cout << "\n   Output: ";
        print_lowmc_state_words64(std::cout, output);
        std::cout << '\n';
    }
#ifdef DEBUG_TOP_MPC
    if (t == 0) {
        std::cout << blue
                  << "\n============ mpc_simulate_and_verify completed "
                     "============\n"
                  << normal;
    }
#endif

    return EXIT_SUCCESS;
}
