/*******************************************************************************
 * File:        Mpc_mfors_authpath.cpp
 * Description: MPC code for a the MFORS authpath (base+top)
 *
 * Author:      Chris Newton
 * Created:     Saturday 4 June 2022
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
#include "Mpc_lowmc.h"
#include "Mpc_hash1.h"
#include "Mpc_parameters.h"
#include "Mpc_signature_utils.h"
#include "Mpc_working_data.h"
#include "Mpc_sign.h"
#include "Mpc_verify.h"
#include "Mpc_node_address.h"
#include "Mfors_tree.h"
#include "Mpc_mfors_authpath.h"

//#define DEBUG_MFORS_AUTHPATH

Mpc_mfors_authpath::Mpc_mfors_authpath(
  Mfors_authpath_ptr mfors_authpath, Mpc_proof_indices const &indices) noexcept
  : mfors_path_ptr_(mfors_authpath), indices_(indices)
{
    base_authpath_indices_ = indices_add_mpc_param(indices_, local_mpc_param_);
    top_authpath_indices_ = indices_add_mpc_param(
      base_authpath_indices_, Mpc_base_authpath::mpc_param_);

    get_param_set(get_picnic_parameter_set_id(), &paramset_);
}

Tape_offset Mpc_mfors_authpath::set_offsets(Tape_offset const &of) noexcept
{
    base_offset_ = of;

    intermediate_mask_offset_ = base_offset_;
    base_offset_ += Lowmc_parameters::lowmc_state_bits_;

    Mpc_base_authpath base_path{ mfors_path_ptr_->base_path_,
        base_authpath_indices_ };
    Mpc_top_authpath top_path{ mfors_path_ptr_->top_path_,
        top_authpath_indices_ };

    Tape_offset next_offset{ base_offset_ };
    next_offset = base_path.set_offsets(next_offset);
    next_offset = top_path.set_offsets(next_offset);

    assertm(next_offset - base_offset_ == path_offset_bits_ + tape_bits_,
      "Mpc_mfors_authpath: inconsistent path offset values");

    return next_offset;
}

void Mpc_mfors_authpath::compute_aux_tape_sign(randomTape_t *tapes,
  Mpc_working_data &mpc_wd, Lowmc_state_words64_const_ptr root_mask,
  size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];// To use internally

    Mpc_base_authpath base_path{ mfors_path_ptr_->base_path_,
        base_authpath_indices_ };
    Mpc_top_authpath top_path{ mfors_path_ptr_->top_path_,
        top_authpath_indices_ };

    Tape_offset next_offset{ base_offset_ };
    next_offset = base_path.set_offsets(next_offset);
    next_offset = top_path.set_offsets(next_offset);

    Lowmc_state_words64 intermediate_hash_mask{ 0 };
    get_mask_from_tapes(intermediate_hash_mask, current_tape_ptr,
      intermediate_mask_offset_, &paramset_);

    base_path.compute_aux_tape_sign(tapes, mpc_wd, intermediate_hash_mask, t);

    top_path.compute_aux_tape_sign(
      tapes, mpc_wd, intermediate_hash_mask, root_mask, t);
}

void Mpc_mfors_authpath::compute_aux_tape_verify(randomTape_t *tapes,
  [[maybe_unused]] Signature_data const &sig_data,
  Lowmc_state_words64_const_ptr root_mask, size_t t) noexcept
{
    randomTape_t *current_tape_ptr = &tapes[t];// To use internally

    Mpc_base_authpath base_path{ mfors_path_ptr_->base_path_,
        base_authpath_indices_ };
    Mpc_top_authpath top_path{ mfors_path_ptr_->top_path_,
        top_authpath_indices_ };

    Tape_offset next_offset{ base_offset_ };
    next_offset = base_path.set_offsets(next_offset);
    next_offset = top_path.set_offsets(next_offset);

    Lowmc_state_words64 intermediate_hash_mask{ 0 };
    get_mask_from_tapes(intermediate_hash_mask, current_tape_ptr,
      intermediate_mask_offset_, &paramset_);

    base_path.compute_aux_tape_verify(
      tapes, sig_data, intermediate_hash_mask, t);

    top_path.compute_aux_tape_verify(
      tapes, sig_data, intermediate_hash_mask, root_mask, t);
}

void Mpc_mfors_authpath::get_aux_bits(uint8_t *aux_bits, Tape_offset &aux_pos,
  randomTape_t *tapes, size_t t) noexcept
{
    Mpc_base_authpath base_path{ mfors_path_ptr_->base_path_,
        base_authpath_indices_ };
    Mpc_top_authpath top_path{ mfors_path_ptr_->top_path_,
        top_authpath_indices_ };

    Tape_offset next_offset{ base_offset_ };
    next_offset = base_path.set_offsets(next_offset);
    next_offset = top_path.set_offsets(next_offset);

    base_path.get_aux_bits(aux_bits, aux_pos, tapes, t);
    top_path.get_aux_bits(aux_bits, aux_pos, tapes, t);

#ifdef DEBUG_MFORS_AUTHPATH
    if (aux_pos != mpc_param_.aux_size_bits_) {
        std::cout << magenta << "Mpc_mfors_authpath: Inconsistent value ("
                  << aux_pos << ") returned from get_aux_bits for t=" << t
                  << '\n'
                  << normal;
    } else {
        std::cout << green << "Mpc_mfors_authpath: Consistent value ("
                  << aux_pos << ") returned from get_aux_bits for t=" << t
                  << '\n'
                  << normal;
    }
#endif
}

void Mpc_mfors_authpath::set_aux_bits(randomTape_t *tapes, Tape_offset &aux_pos,
  Signature_data const &sig_data, size_t t) noexcept
{
    Mpc_base_authpath base_path{ mfors_path_ptr_->base_path_,
        base_authpath_indices_ };
    Mpc_top_authpath top_path{ mfors_path_ptr_->top_path_,
        top_authpath_indices_ };

    Tape_offset next_offset{ base_offset_ };
    next_offset = base_path.set_offsets(next_offset);
    next_offset = top_path.set_offsets(next_offset);

    base_path.set_aux_bits(tapes, aux_pos, sig_data, t);
    top_path.set_aux_bits(tapes, aux_pos, sig_data, t);

#ifdef DEBUG_MFORS_AUTHPATH
    if (aux_pos != mpc_param_.aux_size_bits_) {
        std::cout << magenta << "Mpc_mfors_authpath: Inconsistent value ("
                  << aux_pos << ") returned from get_aux_bits for t=" << t
                  << '\n'
                  << normal;
    } else {
        std::cout << green << "Mpc_mfors_authpath: Consistent value ("
                  << aux_pos << ") returned from get_aux_bits for t=" << t
                  << '\n'
                  << normal;
    }
#endif
}

int Mpc_mfors_authpath::mpc_simulate_sign(randomTape_t *tapes,
  Mpc_working_data &mpc_wd, shares_t *tmp_shares,
  Lowmc_state_words64_ptr output, size_t t) noexcept
{
    Mpc_base_authpath base_path{ mfors_path_ptr_->base_path_,
        base_authpath_indices_ };
    Mpc_top_authpath top_path{ mfors_path_ptr_->top_path_,
        top_authpath_indices_ };

    Tape_offset next_offset{ base_offset_ };
    next_offset = base_path.set_offsets(next_offset);
    next_offset = top_path.set_offsets(next_offset);

    Lowmc_state_words64 intermediate_hash{ 0 };

    int rv = base_path.mpc_simulate_sign(
      tapes, mpc_wd, tmp_shares, intermediate_hash, t);
    if (rv != 0) {
        std::cerr << "MPC simulation, base_authpath, failed for round " << t
                  << ", signature invalid\n";
        return EXIT_FAILURE;
    }

    rv = top_path.mpc_simulate_sign(
      tapes, intermediate_hash, mpc_wd, tmp_shares, output, t);
    if (rv != 0) {
        std::cerr << "MPC simulation, top_authpath, failed for round " << t
                  << ", signature invalid\n";
        return EXIT_FAILURE;
    }

    return rv;
}

int Mpc_mfors_authpath::mpc_simulate_and_verify(randomTape_t *tapes,
  Signature_data const &sig_data, msgs_t *msgs, Lowmc_state_words64_ptr output,
  shares_t *tmp_shares, size_t t) noexcept
{
    Mpc_base_authpath base_path{ mfors_path_ptr_->base_path_,
        base_authpath_indices_ };
    Mpc_top_authpath top_path{ mfors_path_ptr_->top_path_,
        top_authpath_indices_ };

    Tape_offset next_offset{ base_offset_ };
    next_offset = base_path.set_offsets(next_offset);
    next_offset = top_path.set_offsets(next_offset);

    Lowmc_state_words64 intermediate_hash{ 0 };
    int rv = base_path.mpc_simulate_and_verify(
      tapes, sig_data, msgs, intermediate_hash, tmp_shares, t);
    if (rv != 0) {
        std::cerr << "MPC simulation, base_authpath, failed for round " << t
                  << ", signature invalid\n";
        return EXIT_FAILURE;
    }

    rv = top_path.mpc_simulate_and_verify(
      tapes, intermediate_hash, sig_data, msgs, output, tmp_shares, t);
    if (rv != 0) {
        std::cerr << "MPC simulation, top_authpath, failed for round " << t
                  << ", signature invalid\n";
        return EXIT_FAILURE;
    }

    if (Top_authpath::height_ < 5) {
        std::cout << "\nOutput: ";
        print_lowmc_state_words64(std::cout, output);
        std::cout << '\n';
    }

    return EXIT_SUCCESS;
}
