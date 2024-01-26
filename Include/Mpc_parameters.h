/*******************************************************************************
 * File:        MPC_parameters.h
 * Description: Masked MPC parameters
 *
 * Author:      Chris Newton
 *
 * Created:     Wednesday 9 February 2022
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



#ifndef MPC_PARAMS_H
#define MPC_PARAMS_H

#include <limits>
#include <array>

#include "Hbgs_param.h"

using Tape_offset = uint32_t;

constexpr uint32_t null_offset{ std::numeric_limits<uint32_t>::max() };

using Gt_row_type = uint8_t;
using Gt_index_type = uint64_t;
using Mt_tree_type = uint8_t;
using Mt_row_type = uint8_t;
using Mt_index_type = uint16_t;

constexpr static size_t gt_row_bytes = sizeof(Gt_row_type);
constexpr static size_t gt_index_bytes = sizeof(Gt_index_type);
constexpr static size_t mt_tree_bytes = sizeof(Mt_tree_type);
constexpr static size_t mt_row_bytes = sizeof(Mt_row_type);
constexpr static size_t mt_index_bytes = sizeof(Mt_index_type);
constexpr static size_t gt_index_bits = 8 * gt_index_bytes;
constexpr static size_t mt_index_bits = 8 * mt_index_bytes;

enum class Index_parity : Mt_index_type { even = 0, odd = 1 };

static_assert(
  Public_parameters::d_ <= mt_index_bits, "d too large for the assigned type");
static_assert(
  Public_parameters::q_alpha_ * Public_parameters::h_ <= gt_index_bits,
  "q too large for the assigned type");

constexpr static size_t bits_to_bytes(size_t n_bits)
{
    return (n_bits + 7U) / 8U;
}

// The parameters used in the MPC proof
struct Mpc_param
{
    Mpc_param() = default;
    constexpr Mpc_param(size_t aux, size_t n_in, size_t n_mpc, size_t n_out)
      : aux_size_bits_(aux), n_inputs_(n_in), n_mpc_inputs_(n_mpc),
        n_outputs_(n_out)
    {
        aux_size_bytes_ = bits_to_bytes(aux_size_bits_);
    }
    size_t aux_size_bits_{ 0 };// The size of the aux bits
    // The assignment of inputs is rather arbitrary. We could just combine
    // them - keep them separate for now
    size_t n_inputs_{ 0 };// The number of inputs
    size_t n_mpc_inputs_{ 0 };// The number of inputs for the LowMC calculations
    size_t n_outputs_{ 0 };// The number of outputs
    size_t aux_size_bytes_{ 0 };// The size of the aux bits
};

constexpr static Mpc_param operator+(
  Mpc_param const &mpc1, Mpc_param const &mpc2)
{
    Mpc_param mpcr{ mpc1 };
    mpcr.aux_size_bits_ += mpc2.aux_size_bits_;
    mpcr.n_inputs_ += mpc2.n_inputs_;
    mpcr.n_mpc_inputs_ += mpc2.n_mpc_inputs_;
    mpcr.n_outputs_ += mpc2.n_outputs_;

    mpcr.aux_size_bytes_ = (mpcr.aux_size_bits_ + 7U) / 8U;

    return mpcr;
}

constexpr static Mpc_param scale_mpc_param(
  Mpc_param const &mpc1, size_t scale_factor)
{
    Mpc_param mpcr{ mpc1 };
    mpcr.aux_size_bits_ *= scale_factor;
    mpcr.n_mpc_inputs_ *= scale_factor;
    mpcr.n_inputs_ *= scale_factor;
    mpcr.n_outputs_ *= scale_factor;

    mpcr.aux_size_bytes_ = (mpcr.aux_size_bits_ + 7U) / 8U;

    return mpcr;
}

constexpr size_t null_index = std::numeric_limits<size_t>::max();

enum class Mpc_state { signing, verifying };

// The indices to use when saving the proof data
struct Mpc_proof_indices
{
    size_t input_index_{ null_index };
    size_t mpc_input_index_{ null_index };
    size_t output_index_{ null_index };
};

constexpr static Mpc_proof_indices operator+(
  Mpc_proof_indices const &pi1, Mpc_proof_indices const &pi2)
{
    Mpc_proof_indices pir;
    pir.input_index_ = pi1.input_index_ + pi2.input_index_;
    pir.mpc_input_index_ = pi1.mpc_input_index_ + pi2.mpc_input_index_;
    pir.output_index_ = pi1.output_index_ + pi2.output_index_;

    return pir;
}
// Used at the top level to initilise the Mpc_proof_indices from the 'local'
// Mpc_param
constexpr static Mpc_proof_indices indices_from_mpc_param(
  Mpc_param const &param)
{
    Mpc_proof_indices indices;
    indices.input_index_ = param.n_inputs_;
    indices.mpc_input_index_ = param.n_mpc_inputs_;
    indices.output_index_ = param.n_outputs_;

    return indices;
}

// Used to adjust the Mpc_proof_indices from an item's Mpc_param for passing to
// other items (at the same level)
constexpr static Mpc_proof_indices indices_add_mpc_param(
  Mpc_proof_indices const &indices, Mpc_param const &param)
{
    Mpc_proof_indices new_indices;
    new_indices.input_index_ = indices.input_index_ + param.n_inputs_;
    new_indices.mpc_input_index_ =
      indices.mpc_input_index_ + param.n_mpc_inputs_;
    new_indices.output_index_ = indices.output_index_ + param.n_outputs_;

    return new_indices;
}

#endif
