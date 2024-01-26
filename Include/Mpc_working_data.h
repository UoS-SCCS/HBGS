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



#ifndef MPC_WORKING_DATA_H
#define MPC_WORKING_DATA_H

#include <iostream>
#include <cmath>
#include <vector>

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}
#include "Picnic_mpc_functions.h"
#include "Hbgs_param.h"
#include "Mpc_parameters.h"
#include "Mpc_utils.h"

enum mpc_wd_print_mask : uint8_t {
    aux_bits = 1,
    msgs = 2,
    mpc_inputs = 4,
    inputs = 8,
    outputs = 16
};

class Mpc_working_data
{
  public:
    Mpc_working_data() = delete;
    Mpc_working_data(Mpc_param const &param) noexcept;
    ~Mpc_working_data();

    bool is_initialised_{ false };
    size_t aux_size_bytes_{ 0 };
    uint8_t *aux_bits_{ nullptr };// saved aux bits for each round
    msgs_t *msgs_{ nullptr };// One set of each party's messages for each round
    std::vector<inputs_t> mpc_inputs_;// One of each input per MPC round
    std::vector<inputs_t> inputs_;// One of each input per MPC round
    std::vector<inputs_t> outputs_;// One of each output per MPC round
    void print_working_data(std::ostream &os, mpc_wd_print_mask pm);
};

class Commitment_data1
{
  public:
    Commitment_data1() noexcept;
    ~Commitment_data1();

    bool is_initialised{ false };
    commitments_t *C_{ nullptr };
};

class Commitment_data2
{
  public:
    Commitment_data2() noexcept;
    ~Commitment_data2();

    bool is_initialised{ false };
    commitments_t Ch = { nullptr, 0 };
    commitments_t Cv = { nullptr, 0 };
    tree_t *treeCv = nullptr;
};

#endif
