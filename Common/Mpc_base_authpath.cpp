/*******************************************************************************
 * File:        Mpc_base_authpath.cpp
 * Description: MPC code for a base authpath
 *
 * Author:      Chris Newton
 * Created:     Sunday 29 May 2022
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
#include "Merkle_tree.h"
#include "Mpc_base_authpath.h"

//#define DEBUG_BASE_AUTHPATH

Mpc_base_authpath::Mpc_base_authpath(
  Base_authpath const &base_authpath, Mpc_proof_indices const &indices) noexcept
{
    copy_base_authpath(base_path_, base_authpath);
    // OK here as we are only doing a 'base' merkle tree
    M_tree_address mta{ base_authpath.m_tree_, depth_,
        base_authpath.leaf_index_ };
    leaf_node_addr_.set_initial_node_address(base_authpath.gt_addr_, mta);
#ifdef DEBUG_BASE_AUTHPATH
    if (Base_authpath::depth_ < 5) {
        std::cout << "mt: initial_node_address: ";
        print_lowmc_state_words(std::cout, leaf_node_addr_.node_state());
        std::cout << '\n';
        std::cout << "mt:    initial_node_mask: ";
        print_lowmc_state_words(std::cout, leaf_node_addr_.node_mask());
        std::cout << '\n';
    }
#endif

    base_input_index_ = indices.input_index_;
    base_mpc_index_ = indices.mpc_input_index_;
    base_output_index_ = indices.output_index_;

    get_param_set(get_picnic_parameter_set_id(), &paramset_);
}

Tape_offset Mpc_base_authpath::set_offsets(Tape_offset const &of) noexcept
{
    base_offset_ = of;

    base_offset_ = leaf_node_addr_.set_offsets(base_offset_);

    precursor_offset_ = base_offset_;
    base_offset_ += Mpc_parameters::lowmc_state_bits_;

    for (auto &os : path_offsets_) {
        os = base_offset_;
        base_offset_ += Mpc_parameters::lowmc_state_bits_;
    }

    for (auto &os : intermediate_offsets_) {
        os = base_offset_;
        base_offset_ += Mpc_parameters::lowmc_state_bits_;
    }

    assertm(
      base_offset_ == of + local_offset_bits_, "Inconsistent offset values");

    return of + tape_bits_ + offset_bits_;
}

void Mpc_base_authpath::compute_aux_tape_sign(randomTape_t *tapes,
  Mpc_working_data &mpc_wd, Lowmc_state_words64_const_ptr root_mask,
  size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];// To use internally

    Tape_offset next_offset{ base_offset_ };

    Hash1a hash1a;
    next_offset = hash1a.set_offsets(next_offset);

    Node_address_state node_addr{ leaf_node_addr_ };
    node_addr.set_and_apply_initial_mask(tapes, t);
    Lowmc_state_words64_const_ptr node_mask = node_addr.node_mask64();

    Lowmc_state_words64_ptr adjusted_precursor_mask =
      (Word *)mpc_wd.mpc_inputs_[base_mpc_index_][t];

    Lowmc_state_words64 current_hash_mask{ 0 };
    get_mask_from_tapes(current_hash_mask, current_tape_ptr,
      intermediate_offsets_[0], &paramset_);
    hash1a.compute_aux_tape(current_tape_ptr, node_mask, current_hash_mask,
      adjusted_precursor_mask, &paramset_);

    Lowmc_state_words64 precursor_mask{ 0 };
    get_mask_from_tapes(
      precursor_mask, current_tape_ptr, precursor_offset_, &paramset_);
    xor64(adjusted_precursor_mask, precursor_mask);

    Lowmc_state_words64 authpath_mask{ 0 };
    Lowmc_state_words64 next_hash_mask{ 0 };
    for (size_t i = 0; i < depth_; ++i) {
        get_mask_from_tapes(
          authpath_mask, current_tape_ptr, path_offsets_[i], &paramset_);
        if (i != depth_ - 1) {
            get_mask_from_tapes(next_hash_mask, current_tape_ptr,
              intermediate_offsets_[i + 1], &paramset_);
        } else if (root_mask != nullptr) {
            std::memcpy(
              next_hash_mask, root_mask, Mpc_parameters::lowmc_state_bytes_);
        } else {
            std::memset(next_hash_mask, 0, Mpc_parameters::lowmc_state_bytes_);
        }

        node_addr.update_mt_row_and_index();

        Masked_tree_hash masked_tree_hash;
        next_offset = masked_tree_hash.set_offsets(next_offset);

        auto first_mask_adjustment =
          (Word *)mpc_wd.mpc_inputs_[base_mpc_index_ + 2 * i + 1][t];
        auto intermediate_mask_adjustment =
          (Word *)mpc_wd.mpc_inputs_[base_mpc_index_ + 2 * i + 2][t];

        masked_tree_hash.compute_aux_tape(current_tape_ptr, current_hash_mask,
          authpath_mask, node_mask, next_hash_mask, first_mask_adjustment,
          intermediate_mask_adjustment, &paramset_);

        std::memcpy(current_hash_mask, next_hash_mask,
          Mpc_parameters::lowmc_state_bytes_);
    }
}

void Mpc_base_authpath::compute_aux_tape_verify(randomTape_t *tapes,
  [[maybe_unused]] Signature_data const &sig_data,
  Lowmc_state_words64_const_ptr root_mask, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

    Tape_offset next_offset{ base_offset_ };

    Hash1a hash1a;
    next_offset = hash1a.set_offsets(next_offset);

    Node_address_state node_addr{ leaf_node_addr_ };
    node_addr.set_and_apply_initial_mask(tapes, t);
    Lowmc_state_words64_const_ptr node_mask = node_addr.node_mask64();

    Lowmc_state_words64 current_hash_mask{ 0 };
    get_mask_from_tapes(current_hash_mask, current_tape_ptr,
      intermediate_offsets_[0], &paramset_);
    hash1a.compute_aux_tape(
      current_tape_ptr, node_mask, current_hash_mask, nullptr, &paramset_);

    Lowmc_state_words64 authpath_mask{ 0 };
    Lowmc_state_words64 next_hash_mask{ 0 };
    for (size_t i = 0; i < depth_; ++i) {
        get_mask_from_tapes(
          authpath_mask, current_tape_ptr, path_offsets_[i], &paramset_);
        if (i != depth_ - 1) {
            get_mask_from_tapes(next_hash_mask, current_tape_ptr,
              intermediate_offsets_[i + 1], &paramset_);
        } else if (root_mask != nullptr) {
            std::memcpy(
              next_hash_mask, root_mask, Mpc_parameters::lowmc_state_bytes_);
        } else {
            std::memset(next_hash_mask, 0, Mpc_parameters::lowmc_state_bytes_);
        }

        node_addr.update_mt_row_and_index();

        Masked_tree_hash masked_tree_hash;
        next_offset = masked_tree_hash.set_offsets(next_offset);

        masked_tree_hash.compute_aux_tape(current_tape_ptr, current_hash_mask,
          authpath_mask, node_mask, next_hash_mask, nullptr, nullptr,
          &paramset_);

        std::memcpy(current_hash_mask, next_hash_mask,
          Mpc_parameters::lowmc_state_bytes_);
    }
}

void Mpc_base_authpath::get_aux_bits(uint8_t *aux_bits, Tape_offset &aux_pos,
  randomTape_t *tapes, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

    Tape_offset keep_offset = current_tape_ptr->pos;

    Tape_offset next_offset{ base_offset_ };

    Hash1a hash1a;
    next_offset = hash1a.set_offsets(next_offset);

    hash1a.get_aux_bits(aux_bits, aux_pos, current_tape_ptr);

    for (size_t i = 0; i < depth_; ++i) {
        Masked_tree_hash masked_tree_hash;
        next_offset = masked_tree_hash.set_offsets(next_offset);
        masked_tree_hash.get_aux_bits(aux_bits, aux_pos, current_tape_ptr);
    }

    current_tape_ptr->pos = keep_offset;
}

void Mpc_base_authpath::set_aux_bits(randomTape_t *tapes, Tape_offset &aux_pos,
  Signature_data const &sig_data, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

    Tape_offset next_offset{ base_offset_ };

    Hash1a hash1a;
    next_offset = hash1a.set_offsets(next_offset);

    hash1a.set_aux_bits(current_tape_ptr, aux_pos, sig_data.proofs_[t]->aux_);

    for (size_t i = 0; i < depth_; ++i) {
        Masked_tree_hash masked_tree_hash;
        next_offset = masked_tree_hash.set_offsets(next_offset);
        masked_tree_hash.set_aux_bits(
          current_tape_ptr, aux_pos, sig_data.proofs_[t]->aux_);
    }
}

int Mpc_base_authpath::mpc_simulate_sign(randomTape_t *tapes,
  Mpc_working_data &mpc_wd, shares_t *tmp_shares,
  [[maybe_unused]] Lowmc_state_words64_ptr output, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

    Tape_offset next_offset{ base_offset_ };

    Hash1a hash1a;
    next_offset = hash1a.set_offsets(next_offset);

    Lowmc_state_words64 precursor_mask{ 0 };
    get_mask_from_tapes(
      precursor_mask, current_tape_ptr, precursor_offset_, &paramset_);
    xor64((Word *)mpc_wd.inputs_[base_input_index_][t],
      precursor_mask,
      base_path_.leaf_precursor_);

    Node_address_state node_addr{ leaf_node_addr_ };
    node_addr.set_and_apply_initial_mask(tapes, t);

    std::memcpy(mpc_wd.inputs_[base_input_index_ + 1][t],
      node_addr.node_state(), Mpc_parameters::lowmc_state_bytes_);

#ifdef DEBUG_BASE_AUTHPATH
    if (Base_authpath::depth_ < 5) {
        std::cout << "   Masked node address: ";
        print_lowmc_state_words64(std::cout, node_addr.node_state64());
        std::cout << '\n';
        std::cout << "           inputs_: " << base_input_index_ + 1 << ": ";
        print_lowmc_state_words64(
          std::cout, (Word *)mpc_wd.inputs_[base_input_index_ + 1][t]);
        std::cout << '\n';
        Lowmc_state_words64 unmasked_node{ 0 };
        xor64(unmasked_node, node_addr.node_state64(), node_addr.node_mask64());
        std::cout << "Un-masked node address: ";
        print_lowmc_state_words64(std::cout, unmasked_node);
        std::cout << '\n';
    }
#endif
    Lowmc_state_words64 masked_key{ 0 };
    Lowmc_state_words64 current_hash{ 0 };
    xor64(masked_key, (Word *)mpc_wd.mpc_inputs_[base_mpc_index_][t],
      (Word *)mpc_wd.inputs_[base_input_index_][t]);
    int rv = hash1a.mpc_simulate(masked_key,
      (Word *)mpc_wd.inputs_[base_input_index_ + 1][t],
      current_tape_ptr,
      tmp_shares,
      &mpc_wd.msgs_[t],
      current_hash,
      &paramset_);
    if (rv != 0) {
        std::cerr << "MPC simulation, hash1a, failed for round " << t
                  << ", signature invalid\n";
        return EXIT_FAILURE;
    }

#ifdef DEBUG_BASE_AUTHPATH
    if (Base_authpath::depth_ < 5) {
        std::cout << '\n' << t << "         Masked key: ";
        print_lowmc_state_words64(std::cout, masked_key);
        std::cout << '\n' << t << "       Node address: ";
        print_lowmc_state_words64(std::cout, node_addr.node_state64());
        std::cout << '\n' << t << "  Masked first hash: ";
        print_lowmc_state_words64(std::cout, current_hash);
        std::cout << '\n';

        Lowmc_state_words64 current_hash_mask{ 0 };
        get_mask_from_tapes(current_hash_mask, current_tape_ptr,
          intermediate_offsets_[0], &paramset_);
        Lowmc_state_words64 unmasked_hash{ 0 };
        xor64(unmasked_hash, current_hash_mask, current_hash);

        std::cout << "  Un-masked first hash: ";
        print_lowmc_state_words64(std::cout, unmasked_hash);
        std::cout << '\n';
    }
#endif
    Lowmc_state_words64 authpath_mask{ 0 };
    Lowmc_state_words64 next_hash{ 0 };
    uint8_t lsb{ 0xff };
    for (size_t i = 0; i < depth_; ++i) {
        get_mask_from_tapes(
          authpath_mask, current_tape_ptr, path_offsets_[i], &paramset_);

        lsb = node_addr.lsb_bit();

        node_addr.update_mt_row_and_index();

#ifdef DEBUG_BASE_AUTHPATH
        std::cout << "\nlsb: " << 0 + lsb << '\n';
        std::cout << "Node address: ";
        print_lowmc_state_words64(std::cout, node_addr.node_state64());
        std::cout << '\n';
#endif
        size_t mpc_index_base = base_mpc_index_ + 2 * i + 1;
        size_t input_index_base = base_input_index_ + 3 * i + 2;

        auto extended_masked_b = (Word *)mpc_wd.inputs_[input_index_base][t];

        Lowmc_state_words64_const_ptr auth = base_path_.path_[i];
        auto masked_auth = (Word *)mpc_wd.inputs_[input_index_base + 1][t];
        xor64(masked_auth, auth, authpath_mask);

        auto masked_node = (Word *)mpc_wd.inputs_[input_index_base + 2][t];
        std::memcpy(
          masked_node, node_addr.node_state64(), paramset_.stateSizeBytes);

        auto first_mask_adjustment =
          (Word *)mpc_wd.mpc_inputs_[mpc_index_base][t];
        auto intermediate_mask_adjustment =
          (Word *)mpc_wd.mpc_inputs_[mpc_index_base + 1][t];

        msgs_t *msgs = &mpc_wd.msgs_[t];

        Masked_tree_hash masked_tree_hash;
        next_offset = masked_tree_hash.set_offsets(next_offset);

        Tape_offset cmask_offset = intermediate_offsets_[i];
        Tape_offset amask_offset = path_offsets_[i];

        rv = masked_tree_hash.mpc_simulate_sign(current_tape_ptr, current_hash,
          masked_auth, masked_node, cmask_offset, amask_offset, lsb, tmp_shares,
          msgs, extended_masked_b, first_mask_adjustment,
          intermediate_mask_adjustment, next_hash, &paramset_);
        if (rv != 0) {
            std::cerr << "MPC simulation, masked tree hash, for i=" << i
                      << " failed for round " << t << ", signature invalid\n";
            return EXIT_FAILURE;
        }

#ifdef DEBUG_BASE_AUTHPATH
        if (i != (depth_ - 1)) {
            Lowmc_state_words64 next_hash_mask{ 0 };
            get_mask_from_tapes(next_hash_mask, current_tape_ptr,
              intermediate_offsets_[i + 1], &paramset_);
            if (Base_authpath::depth_ < 5) {
                Lowmc_state_words64 unmasked_hash{ 0 };
                xor64(unmasked_hash, next_hash_mask, next_hash);
                std::cout << "  Un-masked hash " << i << ": ";
                print_lowmc_state_words64(std::cout, unmasked_hash);
                std::cout << '\n';
            }
        }
#endif

        std::memcpy(
          current_hash, next_hash, Mpc_parameters::lowmc_state_bytes_);
    }

    std::memcpy(output, current_hash, Mpc_parameters::lowmc_state_bytes_);

    return rv;
}

int Mpc_base_authpath::mpc_simulate_and_verify(randomTape_t *tapes,
  Signature_data const &sig_data, msgs_t *msgs, Lowmc_state_words64_ptr output,
  shares_t *tmp_shares, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];

    Tape_offset next_offset{ base_offset_ };

    Hash1a hash1a;
    next_offset = hash1a.set_offsets(next_offset);

    Lowmc_state_words64_const_ptr node_addr =
      (Word *)sig_data.proofs_[t]->inputs_[base_input_index_ + 1];

#ifdef DEBUG_BASE_AUTHPATH
    if (Base_authpath::depth_ < 5) {
        std::cout << '\n'
                  << t << "     inputs_: " << base_input_index_ + 1 << ": ";
        print_lowmc_state_words64(std::cout,
          (Word *)sig_data.proofs_[t]->inputs_[base_input_index_ + 1]);
        std::cout << '\n' << t << "       Node address: ";
        print_lowmc_state_words64(std::cout, node_addr);
        std::cout << '\n';
    }
#endif
    Lowmc_state_words64 masked_key{ 0 };
    Lowmc_state_words64 current_hash{ 0 };
    xor64(masked_key, (Word *)sig_data.proofs_[t]->mpc_inputs_[base_mpc_index_],
      (Word *)sig_data.proofs_[t]->inputs_[base_input_index_]);
    int rv = hash1a.mpc_simulate(masked_key,
      node_addr,
      current_tape_ptr,
      tmp_shares,
      msgs,
      current_hash,
      &paramset_);
    if (rv != 0) {
        std::cerr << "MPC simulation, hash1a, failed for round " << t
                  << ", signature invalid\n";
        return EXIT_FAILURE;
    }
#ifdef DEBUG_BASE_AUTHPATH
    if (Base_authpath::depth_ < 5) {

        std::cout << '\n' << t << "         Masked key: ";
        print_lowmc_state_words64(std::cout, masked_key);
        std::cout << '\n' << t << "       Node address: ";
        print_lowmc_state_words64(std::cout, node_addr);
        std::cout << '\n' << t << "  Masked first hash: ";
        print_lowmc_state_words64(std::cout, current_hash);
        std::cout << '\n';
    }
#endif

    Lowmc_state_words64 next_hash{ 0 };
    for (size_t i = 0; i < depth_; ++i) {
        size_t mpc_index_base = base_mpc_index_ + 2 * i + 1;
        size_t input_index_base = base_input_index_ + 3 * i + 2;

        auto extended_masked_b =
          (Word *)sig_data.proofs_[t]->inputs_[input_index_base];

        auto masked_auth =
          (Word *)sig_data.proofs_[t]->inputs_[input_index_base + 1];

        auto masked_node =
          (Word *)sig_data.proofs_[t]->inputs_[input_index_base + 2];

        auto first_mask_adjustment =
          (Word *)sig_data.proofs_[t]->mpc_inputs_[mpc_index_base];

        auto intermediate_mask_adjustment =
          (Word *)sig_data.proofs_[t]->mpc_inputs_[mpc_index_base + 1];

        Masked_tree_hash masked_tree_hash;
        next_offset = masked_tree_hash.set_offsets(next_offset);

        Tape_offset cmask_offset = intermediate_offsets_[i];
        Tape_offset amask_offset = path_offsets_[i];

        rv = masked_tree_hash.mpc_simulate_and_verify(current_tape_ptr,
          current_hash, masked_auth, masked_node, cmask_offset, amask_offset,
          tmp_shares, msgs, extended_masked_b, first_mask_adjustment,
          intermediate_mask_adjustment, next_hash, &paramset_);
        if (rv != 0) {
            std::cerr << "MPC simulation, masked tree hash, for i=" << i
                      << " failed for round " << t << ", signature invalid\n";
            return EXIT_FAILURE;
        }

        std::memcpy(
          current_hash, next_hash, Mpc_parameters::lowmc_state_bytes_);
    }

    std::memcpy(output, current_hash, Mpc_parameters::lowmc_state_bytes_);

#ifdef DEBUG_BASE_AUTHPATH
    if (Base_authpath::depth_ < 5) {
        std::cout << "\nOutput: ";
        print_lowmc_state_words64(std::cout, output);
        std::cout << '\n';
    }
#endif
    return EXIT_SUCCESS;
}
