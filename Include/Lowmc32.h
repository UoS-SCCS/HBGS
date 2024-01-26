/*******************************************************************************
 * File:        Mpc_lowmc.h
 * Description: Utilities used for MPC
 *
 * Author:      Chris Newton
 *
 * Created:     Friday 28 January 2022
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



#ifndef LOWMC32_H
#define LOWMC32_H

#include <iostream>
#include <fstream>
#include <cmath>

extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}

#include "Hbgs_param.h"
#include "Mpc_parameters.h"

using Lowmc_state_words = uint32_t[Mpc_parameters::lowmc_state_words_];
using Lowmc_state_words_ptr = uint32_t *;
using Lowmc_state_words_const_ptr = uint32_t const *;
using Lowmc_state_bytes = uint8_t[Mpc_parameters::lowmc_state_bytes_];
using Lowmc_state_bytes_ptr = uint8_t *;
using Lowmc_state_bytes_const_ptr = uint8_t const *;


void print_lowmc_state_bytes(
  std::ostream &os, Lowmc_state_bytes_const_ptr state_ptr) noexcept;

void print_lowmc_state_words(
  std::ostream &os, Lowmc_state_words_const_ptr state_ptr) noexcept;

bool read_lowmc_state_words(std::ifstream &is, Lowmc_state_words_ptr state_ptr);

bool read_lowmc_state_bytes(std::ifstream &is, Lowmc_state_bytes_ptr state_ptr);

void hash1a(Lowmc_state_words_ptr hash, Lowmc_state_words_const_ptr a,
  Lowmc_state_words_const_ptr b, paramset_t *params) noexcept;

void hash1b(Lowmc_state_words_ptr hash, Lowmc_state_words_const_ptr a,
  Lowmc_state_words_const_ptr b, Lowmc_state_words_const_ptr c,
  paramset_t *params) noexcept;

#endif
