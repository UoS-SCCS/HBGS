/*******************************************************************************
 * File:        Mpc_switch.h
 * Description: Code for MPC Switch, used when traversing the tree with
 * 				masked index
 *
 * Author:      Chris Newton
 *
 * Created:     Tuesday 15 March 2022
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



#ifndef MPC_SWITCH_H
#define MPC_SWITCH_H

#include <iostream>
#include <cmath>

extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}

#include "Hbgs_param.h"
#include "Mpc_parameters.h"
#include "Mpc_utils.h"
#include "Mpc_lowmc.h"


class Mpc_switch
{
  public:
    Mpc_switch() = default;
    Tape_offset set_offsets(Tape_offset const &of) noexcept;
    void compute_aux_tape(randomTape_t *current_tape_ptr,
      Lowmc_state_words64_const_ptr bit_mask,
      Lowmc_state_words64_const_ptr ca_mask,
      Lowmc_state_words64_const_ptr w_mask, paramset_t *params) const noexcept;
    int mpc_simulate(Lowmc_state_words64_const_ptr extended_masked_b,
      Lowmc_state_words64_const_ptr masked_c,
      Lowmc_state_words64_const_ptr masked_a, randomTape_t *current_tape_ptr,
      Tape_offset bit_mask_offset, Tape_offset c_mask_offset,
      Tape_offset a_mask_offset, msgs_t *msgs, Lowmc_state_words64_ptr output,
      paramset_t *params) const noexcept;
    void get_aux_bits(uint8_t *output, uint32_t &pos,
      randomTape_t *current_tape_ptr) const noexcept;
    void set_aux_bits(randomTape_t *current_tape_ptr, uint32_t &pos,
      uint8_t *input) const noexcept;

    constexpr static Tape_offset offset_bits_{ 0 };
    constexpr static Tape_offset aux_bits_{ Mpc_parameters::lowmc_state_bits_ };
    constexpr static Tape_offset tape_bits_{
        Mpc_parameters::lowmc_state_bits_
    };

  private:
    Tape_offset mpc_and_tape_offset_{ null_offset };
};

#endif
