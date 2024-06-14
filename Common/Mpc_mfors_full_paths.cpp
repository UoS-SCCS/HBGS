/*******************************************************************************
 * File:        Mpc_mfors_full_paths.cpp
 * Description: Code for the MFORS authpaths, starting from the initial hash
 *
 * Author:      Chris Newton
 * Created:     Saturday 23 July 2022
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
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include "Io_utils.h"

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
}

#include "Hbgs_param.h"
#include "Picnic_mpc_functions.h"
#include "Mpc_lowmc64.h"
#include "Mpc_utils.h"
#include "Merkle_tree.h"
#include "Mfors_tree.h"
#include "Mpc_node_address.h"
#include "Mpc_base_authpath.h"
#include "Mpc_top_authpath.h"
#include "Mpc_mfors_authpath.h"
#include "Mpc_parameters.h"
#include "Hbgs_issuer.h"
#include "Mpc_sign.h"
#include "Mpc_verify.h"
#include "Mpc_mfors_full_paths.h"

//#define DEBUG_MPC_FULL_PATHS
//#define DEBUG_MPC_FULL_PATHS2

Mpc_mfors_full_paths::Mpc_mfors_full_paths(
  Mfors_tree_paths *tree_paths_ptr, Mpc_proof_indices const &indices) noexcept
  : mpc_indices_(indices), tree_paths_ptr_(tree_paths_ptr)
{
    mfors_authpath_indices_ =
      indices_add_mpc_param(mpc_indices_, local_mpc_param_);

    get_param_set(get_picnic_parameter_set_id(), &paramset_);
}

void Mpc_mfors_full_paths::set_authpath(size_t t) noexcept
{
    auto path_no = static_cast<Mt_tree_type>(t % Tree_parameters::k_);
    if (path_no != current_path_no_) {
        current_path_no_ = path_no;
        mpc_data_.reset(
          new Mpc_mfors_authpath(&tree_paths_ptr_->authpaths_[current_path_no_],
            mfors_authpath_indices_));
        assertm(mpc_data_->mfors_path_ptr_->top_path_.base_tree_no_
                  == current_path_no_,
          "Inconsistent path and base tree number");
        mpc_data_->set_offsets(base_offset_);
#ifdef DEBUG_MPC_FULL_PATHS2
        std::cout << "t=" << t << " path set to number " << 0 + current_path_no_
                  << std::flush;
#endif
    }
}

Tape_offset Mpc_mfors_full_paths::set_offsets(Tape_offset const &of) noexcept
{
    base_offset_ = of;

    Tape_offset next_offset = base_offset_;
    // Set up an initial path to test
    current_path_no_ = 0;
    mpc_data_.reset(new Mpc_mfors_authpath(
      &tree_paths_ptr_->authpaths_[current_path_no_], mfors_authpath_indices_));
    assertm(
      mpc_data_->mfors_path_ptr_->top_path_.base_tree_no_ == current_path_no_,
      "Inconsistent path and base tree number");

#ifdef DEBUG_MPC_FULL_PATHS2
    std::cout << "set_offsets: path set to number " << 0 + current_path_no_
              << '\n';
#endif
    next_offset = mpc_data_->set_offsets(next_offset);

    assertm(next_offset - of == tape_bits_ + offset_bits_,
      "Mfors_mfors_h2_paths: inconsistent offsets");

    return next_offset;
}

void Mpc_mfors_full_paths::compute_aux_tape_sign(randomTape_t *tapes,
  Lowmc_state_words64_const_ptr root_mask, Mpc_working_data &mpc_wd,
  size_t t) noexcept
{
    set_authpath(t);

    mpc_data_->compute_aux_tape_sign(tapes, mpc_wd, root_mask, t);
}

void Mpc_mfors_full_paths::compute_aux_tape_verify(randomTape_t *tapes,
  Lowmc_state_words64_const_ptr root_mask,
  [[maybe_unused]] Signature_data const &sig_data, size_t t) noexcept
{
    set_authpath(t);

    mpc_data_->compute_aux_tape_verify(tapes, sig_data, root_mask, t);
}

void Mpc_mfors_full_paths::get_aux_bits(uint8_t *aux_bits, Tape_offset &aux_pos,
  randomTape_t *tapes, size_t t) noexcept
{
    set_authpath(t);
    mpc_data_->get_aux_bits(aux_bits, aux_pos, tapes, t);
}

void Mpc_mfors_full_paths::set_aux_bits(randomTape_t *tapes,
  Tape_offset &aux_pos, Signature_data const &sig_data, size_t t) noexcept
{
    set_authpath(t);
    mpc_data_->set_aux_bits(tapes, aux_pos, sig_data, t);
}

int Mpc_mfors_full_paths::mpc_simulate_sign(randomTape_t *tapes,
  Lowmc_state_words64_ptr output, Mpc_working_data &mpc_wd,
  shares_t *tmp_shares, size_t t) noexcept
{
    set_authpath(t);

    int rv = mpc_data_->mpc_simulate_sign(tapes, mpc_wd, tmp_shares, output, t);

#ifdef DEBUG_MPC_FULL_PATHS
    if (t < 3) {
        std::cout << "t=" << t << " FP S output: ";
        print_lowmc_state_words64(std::cout, output);
        std::cout << "\n";
    }
#endif

    return rv;
}

int Mpc_mfors_full_paths::mpc_simulate_verify(randomTape_t *tapes,
  Signature_data const &sig_data, msgs_t *msgs, Lowmc_state_words64_ptr output,
  shares_t *tmp_shares, size_t t) noexcept
{
    set_authpath(t);

    int rv = mpc_data_->mpc_simulate_and_verify(
      tapes, sig_data, msgs, output, tmp_shares, t);

#ifdef DEBUG_MPC_FULL_PATHS
    if (t < 3) {
        std::cout << "t=" << t << " FP V output: ";
        print_lowmc_state_words64(std::cout, output);
        std::cout << "\n\n";
    }
#endif

    return rv;
}
