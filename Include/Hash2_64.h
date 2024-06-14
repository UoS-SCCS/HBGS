/*******************************************************************************
 * File:        Hash2_64.h
 * Description: Hash2 function derived from hash1a64
 *
 * Author:      Chris Newton
 *
 * Created:     Wednesday 14 September 2022
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



#ifndef HASH2_64_H
#define HASH2_64_H

#include "Io_utils.h"

#include <iostream>
#include <cmath>

extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}

#include "Hbgs_param.h"
#include "Lowmc64.h"
#include "Mpc_utils.h"


constexpr uint32_t calculate_n_hashes()
{
    uint32_t bits_required = Tree_parameters::k_ * Tree_parameters::d_;
    uint32_t n_hashes = 1;
    while (n_hashes * Lowmc_parameters::lowmc_state_bits_ < bits_required) {
        n_hashes++;
    }
    return n_hashes;
}

constexpr static uint32_t n_hashes = calculate_n_hashes();

using H2_data64 = std::array<Lowmc_state_words64, n_hashes>;

void print_h2_data(std::ostream &os, H2_data64 const &h2d);

bool read_h2_data(std::ifstream &is, H2_data64 &h2d);

void set_hash2_counter(Lowmc_state_words64_ptr ctr, uint32_t value);

void hash2_64(H2_data64 &hashes, Lowmc_state_words64_const_ptr h1,
  paramset_t *params) noexcept;

#endif
