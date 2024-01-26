/*******************************************************************************
 * File:        Mpc_sign_mfors.cpp
 * Description: Code for signing one of the MFORS tree
 *
 * Author:      Chris Newton
 * Created:     Wednesday 27 July 2022
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
#include <random>
#include "Io_utils.h"


#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
}

#include "Hbgs_param.h"
#include "Picnic_mpc_functions.h"
#include "Mpc_lowmc.h"
#include "Mpc_utils.h"

#include "Mfors_tree.h"
#include "Group_authpaths.h"
#include "Mpc_node_address.h"
#include "Mpc_base_authpath.h"
#include "Mpc_top_authpath.h"
#include "Mpc_mfors_authpath.h"
#include "Mpc_parameters.h"
#include "Hbgs_issuer.h"
#include "Mpc_sign.h"
#include "Mpc_verify.h"
#include "Mpc_sign_mfors.h"

//#define DEBUG_SIGN_MFORS

Mpc_sign_mfors::Mpc_sign_mfors(
  Mfors_tree_paths *mf_tree_path_ptr, Mpc_proof_indices const &indices) noexcept
  : mpc_indices_(indices)
{
    get_param_set(get_picnic_parameter_set_id(), &paramset_);

    mpc_indices_out_ = mpc_indices_ + indices_from_mpc_param(local_mpc_param_);

    mpc_mfors_paths_.reset(
      new Mpc_mfors_full_paths(mf_tree_path_ptr, mpc_indices_out_));
}

Tape_offset Mpc_sign_mfors::set_offsets(Tape_offset const &of) noexcept
{
    base_offset_ = of;

    Tape_offset next_offset = mpc_mfors_paths_->set_offsets(base_offset_);

    return next_offset + tape_bits_;
}

void Mpc_sign_mfors::compute_aux_tape_sign(randomTape_t *tapes,
  Lowmc_state_words64_const_ptr root_mask, Mpc_working_data &mpc_wd,
  size_t t) noexcept
{
    mpc_mfors_paths_->compute_aux_tape_sign(tapes, root_mask, mpc_wd, t);
}

void Mpc_sign_mfors::compute_aux_tape_verify(randomTape_t *tapes,
  Lowmc_state_words64_const_ptr root_mask,
  [[maybe_unused]] Signature_data const &sig_data, size_t t) noexcept
{
    mpc_mfors_paths_->compute_aux_tape_verify(tapes, root_mask, sig_data, t);
}

void Mpc_sign_mfors::get_aux_bits(uint8_t *aux_bits, Tape_offset &aux_pos,
  randomTape_t *tapes, size_t t) noexcept
{
    mpc_mfors_paths_->get_aux_bits(aux_bits, aux_pos, tapes, t);
}

void Mpc_sign_mfors::set_aux_bits(randomTape_t *tapes, Tape_offset &aux_pos,
  Signature_data const &sig_data, size_t t) noexcept
{
    mpc_mfors_paths_->set_aux_bits(tapes, aux_pos, sig_data, t);
}

int Mpc_sign_mfors::mpc_simulate_sign(randomTape_t *tapes,
  Lowmc_state_words64_ptr output, Mpc_working_data &mpc_wd,
  shares_t *tmp_shares, size_t t) noexcept
{
    int rv =
      mpc_mfors_paths_->mpc_simulate_sign(tapes, output, mpc_wd, tmp_shares, t);
    if (rv != 0) {
        std::cerr << "mpc_simulate_sign failed for t=" << t << '\n';
        return EXIT_FAILURE;
    }
#ifdef DEBUG_SIGN_MFORS
    if (t < 3) {
        std::cout << "t=" << t << " SM S output: ";
        print_lowmc_state_words64(std::cout, output);
        std::cout << "\n";
        print_proof_indices(std::cout, mpc_indices_);
        std::cout << '\n';
    }
#endif
    return rv;
}

int Mpc_sign_mfors::mpc_simulate_verify(randomTape_t *tapes,
  Signature_data const &sig_data, msgs_t *msgs, Lowmc_state_words64_ptr output,
  shares_t *tmp_shares, size_t t) noexcept
{

    int rv = mpc_mfors_paths_->mpc_simulate_verify(
      tapes, sig_data, msgs, output, tmp_shares, t);
    if (rv != 0) {
        std::cerr << "mpc_simulate_verify failed for t=" << t << '\n';
        return EXIT_FAILURE;
    }

#ifdef DEBUG_SIGN_MFORS
    if (t < 3) {
        std::cout << "t=" << t << " SM V output: ";
        print_lowmc_state_words64(std::cout, output);
        std::cout << "\n";
        print_proof_indices(std::cout, mpc_indices_);
        std::cout << "\n\n";
    }
#endif
    return EXIT_SUCCESS;
}
