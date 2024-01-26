/*******************************************************************************
 * File:        Hash2_32.cpp
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



#include <iostream>
#include <cmath>

#include "Hbgs_param.h"
#include "Mem_uint.h"
#include "Lowmc32.h"
#include "Hash2_32.h"

void set_hash2_counter(Lowmc_state_words_ptr ctr, uint32_t value)
{
    assertm(value < 256, "Counter value out of bounds");
    auto ctr_ptr = reinterpret_cast<uint8_t *>(ctr);
    ctr_ptr[0] = static_cast<uint8_t>(value);
}

void hash2(
  H2_data &hashes, Lowmc_state_words_const_ptr h1, paramset_t *params) noexcept
{
    Lowmc_state_words ctr{ 0 };
    for (uint32_t c = 0; c < n_hashes; ++c) {
        set_hash2_counter(ctr, c);
        Lowmc_state_words_ptr hash = hashes[c];
        hash1a(hash, h1, ctr, params);
    }
}

void print_h2_data(std::ostream &os, H2_data const &h2d)
{
    for (size_t i = 0; i < h2d.size(); ++i) {
        print_lowmc_state_bytes(os, (uint8_t *)h2d[i]);
        os << '\n';
    }
}

bool read_h2_data(std::ifstream &is, H2_data &h2d)
{
    for (size_t i = 0; i < h2d.size(); ++i) {
        if (!read_lowmc_state_bytes(is, (uint8_t *)h2d[i])) {
            std::cerr << "Error reading the h2 data\n";
            return false;
        };
        std::cout << "i=" << i << '\n';
    }
    return true;
}
