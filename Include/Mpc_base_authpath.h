/*******************************************************************************
 * File:        Mpc_base_authputh.h
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



#ifndef MPC_BASE_AUTHPATH_H
#define MPC_BASE_AUTHPATH_H

#include <array>

#include "Clock_utils.h"
#include "Hbgs_param.h"
#include "Mpc_lowmc.h"
#include "Mpc_hash1.h"
#include "Mpc_working_data.h"
#include "Mpc_signature_utils.h"
#include "Mpc_parameters.h"
#include "Mpc_node_address.h"
#include "Mpc_tree_hash.h"
#include "Merkle_tree.h"

class Mpc_base_authpath
{
  public:
    Mpc_base_authpath() = delete;
    Mpc_base_authpath(Base_authpath const &base_authpath,
      Mpc_proof_indices const &indices) noexcept;
    Tape_offset set_offsets(Tape_offset const &of) noexcept;
    void compute_aux_tape_sign(randomTape_t *tapes, Mpc_working_data &mpc_wd,
      Lowmc_state_words64_const_ptr root_mask, size_t t) noexcept;
    void compute_aux_tape_verify(randomTape_t *tapes,
      [[maybe_unused]] Signature_data const &sig_data,
      Lowmc_state_words64_const_ptr root_mask, size_t t) noexcept;
    void get_aux_bits(uint8_t *aux_bits, Tape_offset &aux_pos,
      randomTape_t *tapes, size_t t) noexcept;
    void set_aux_bits(randomTape_t *tapes, Tape_offset &aux_pos,
      Signature_data const &sig_data, size_t t) noexcept;
    int mpc_simulate_sign(randomTape_t *tapes, Mpc_working_data &mpc_wd,
      shares_t *tmp_shares, Lowmc_state_words64_ptr output, size_t t) noexcept;
    int mpc_simulate_and_verify(randomTape_t *tapes,
      Signature_data const &sig_data, msgs_t *msgs,
      Lowmc_state_words64_ptr output, shares_t *tmp_shares, size_t t) noexcept;

    constexpr static uint8_t depth_ = Base_authpath::depth_;

    constexpr static Tape_offset path_offset_bits_ =
      (depth_ + 1)
      * Mpc_parameters::lowmc_state_bits_;// Precursor and path masks

    constexpr static Tape_offset local_offset_bits_ =
      path_offset_bits_// For the authpath values
      + Node_address_state::offset_bits_// mask for node address
      + depth_
          * Mpc_parameters::lowmc_state_bits_;// masks for intermediate results,

    constexpr static Tape_offset offset_bits_ =
      local_offset_bits_ + Hash1a::offset_bits_// Masks used in Hash1a
      + depth_
          * Masked_tree_hash::offset_bits_;// Masks used in Masked_tree_hash
                                           // excludes the top (root) node;

    constexpr static Tape_offset tape_bits_ =
      depth_ * Masked_tree_hash::tape_bits_ + Hash1a::tape_bits_;

    constexpr static Tape_offset aux_bits_ =
      depth_ * Masked_tree_hash::aux_bits_ + Hash1a::aux_bits_;

    constexpr static Mpc_param mpc_param_{ aux_bits_, 3 * depth_ + 2,
        2 * depth_ + 1, 0 };

  private:
    Base_authpath base_path_{};

    paramset_t paramset_;
    Node_address_state leaf_node_addr_;

    Tape_offset base_offset_{ null_offset };

    Tape_offset precursor_offset_{ null_offset };
    std::array<Tape_offset, Base_authpath::depth_> path_offsets_{ null_offset };
    std::array<Tape_offset, Base_authpath::depth_> intermediate_offsets_{
        null_offset
    };

    size_t base_mpc_index_{ null_index };
    size_t base_input_index_{ null_index };
    size_t base_output_index_{ null_index };
};

#endif
