/*******************************************************************************
 * File:        Mpc_working_data.h
 * Description: Working data used in the LowMC MPC proofs derived from the
 *              picnic code
 *
 * Author:      Chris Newton
 *
 * Created:     Tuesday 22 February 2022
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



#include <iostream>
#include <cmath>
#include "Io_utils.h"

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}
#include "Picnic_mpc_functions.h"
#include "Mpc_utils.h"
#include "Lowmc64.h"
#include "Mpc_parameters.h"
#include "Mpc_working_data.h"

inputs_t allocate_inputs64()
{
    uint8_t *slab = static_cast<uint8_t *>(calloc(1,
      Mpc_parameters::mpc_rounds_
        * (lowmc_state_words64_bytes + sizeof(uint8_t *))));
    // Add this test for success allocating the memory
    if (slab == NULL) { return NULL; }

    inputs_t inputs = (uint8_t **)slab;

    slab += Mpc_parameters::mpc_rounds_ * sizeof(uint8_t *);

    for (uint32_t i = 0; i < Mpc_parameters::mpc_rounds_; i++) {
        inputs[i] = (uint8_t *)slab;
        slab += lowmc_state_words64_bytes;
    }

    return inputs;
}

Mpc_working_data::Mpc_working_data(Mpc_param const &param) noexcept
{
    aux_size_bytes_ = param.aux_size_bytes_;
    paramset_t paramset;
    [[maybe_unused]] int ret =
      get_param_set(get_picnic_parameter_set_id(), &paramset);
    aux_bits_ = static_cast<uint8_t *>(calloc(aux_size_bytes_, 1));
    if (aux_bits_ == nullptr) { return; }

    // Currently using picnic allocation functions - no status returned
    msgs_ = allocate_msgs(&paramset, aux_size_bytes_);

    inputs_.resize(param.n_inputs_);
    for (size_t i = 0; i < param.n_inputs_; ++i) {
        inputs_[i] = allocate_inputs64();
    }

    mpc_inputs_.resize(param.n_mpc_inputs_);
    for (size_t i = 0; i < param.n_mpc_inputs_; ++i) {
        mpc_inputs_[i] = allocate_inputs64();
    }

    outputs_.resize(param.n_outputs_);
    for (size_t i = 0; i < param.n_outputs_; ++i) {
        outputs_[i] = allocate_inputs64();
    }


    is_initialised_ = true;
}

Mpc_working_data::~Mpc_working_data()
{
    freeMsgs(msgs_);

    if (aux_bits_ != nullptr) { free(aux_bits_); }

    for (auto &m : inputs_) { freeInputs(m); }

    for (auto &m : mpc_inputs_) { freeInputs(m); }

    for (auto &m : outputs_) { freeInputs(m); }

    is_initialised_ = false;
}

void Mpc_working_data::print_working_data(
  std::ostream &os, mpc_wd_print_mask pm)
{
    os << "Mpc_working_data\n";
    if (!is_initialised_) {
        os << red << "not initialised\n" << normal;
        return;
    }

    if (pm & mpc_wd_print_mask::aux_bits) {
        os << "aux_bits: ";
        print_buffer(os, aux_bits_, aux_size_bytes_);
        os << '\n';
    }

    if (pm & mpc_wd_print_mask::msgs) { os << "print msgs soon\n"; }

    if (pm & mpc_wd_print_mask::mpc_inputs) {
        size_t n_mpc_inputs = mpc_inputs_.size();
        os << n_mpc_inputs << " mpc_inputs:\n";
        for (auto &m : mpc_inputs_) {
            for (size_t t = 0; t < Mpc_parameters::mpc_rounds_; ++t) {
                os << t << ": ";
                print_lowmc_state_words(os, (uint32_t *)m[t]);
                os << '\n';
            }
        }
    }

    if (pm & mpc_wd_print_mask::inputs) { os << "print inputs soon\n"; }

    if (pm & mpc_wd_print_mask::outputs) { os << "print outputs soon\n"; }
}


Commitment_data1::Commitment_data1() noexcept
{
    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);
    C_ = allocateCommitments(&paramset, 0);
    is_initialised = true;
}

Commitment_data1::~Commitment_data1() { freeCommitments(C_); }

Commitment_data2::Commitment_data2() noexcept
{
    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);
    allocateCommitments2(&Ch, &paramset, paramset.numMPCRounds);
    allocateCommitments2(&Cv, &paramset, paramset.numMPCRounds);
    treeCv = createTree(paramset.numMPCRounds, paramset.digestSizeBytes);
    is_initialised = true;
}

Commitment_data2::~Commitment_data2()
{
    freeCommitments2(&Ch);
    freeCommitments2(&Cv);
    freeTree(treeCv);
    is_initialised = false;
}
