/*******************************************************************************
 * File:        Mpc_utils.h
 * Description: Utilities used for MPC
 *
 * Author:      Chris Newton
 *
 * Created:     Monday 17 January 2022
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



#ifndef MPC_UTILS_H
#define MPC_UTILS_H

#include <iostream>
#include <memory>
#include <cmath>

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "lowmc_constants.h"
}

#include "Mpc_parameters.h"
#include "Lowmc64.h"

picnic_params_t get_picnic_parameter_set_id();

// From picnic, but not declared in the headers
extern "C" {
int get_param_set(picnic_params_t picnicParams, paramset_t *paramset);
}

bool model_parameters_check_ok();

void print_picnic_parameters(std::ostream &os);

void print_hbgs_parameters(std::ostream &os);

void print_mpc_param(std::ostream &os, Mpc_param const &mpc_param);

void print_proof_indices(std::ostream &os, Mpc_proof_indices const &indices);

void print_random_tapes(
  std::ostream &os, randomTape_t *tapes, size_t tape_size);

void allocate_random_tapes(
  randomTape_t *tape, size_t tape_size_bytes, paramset_t *params);

void create_random_tapes(randomTape_t *tapes,
  uint8_t **seeds,
  uint8_t *salt,
  uint16_t t,
  size_t tape_size_bytes,
  paramset_t *params);

void create_random_tapes_times4(randomTape_t *tapes,
  uint8_t **seeds,
  uint8_t *salt,
  size_t t,
  size_t tape_size_bytes,
  paramset_t *params);

// Utiltity function (not in picnic)
void get_mask_from_tapes(
  uint32_t *mask, randomTape_t *tapes, uint32_t offset, paramset_t *params);

void get_mask_from_tapes(
  Word *mask, randomTape_t *tapes, uint32_t offset, paramset_t *params);

msgs_t *allocate_msgs(paramset_t *params, size_t msgs_size);

void free_msgs(msgs_t *msgs);

using Msgs_ptr = std::unique_ptr<msgs_t, decltype(&::free_msgs)>;

void calculate_challenge_lists(uint8_t *challengeHash, uint16_t *challengeC,
  uint16_t *challengeP, paramset_t *params);

void calcualte_challenge_lists16(
  uint8_t *challenge_hash, uint16_t *challengeC, uint16_t *challengeP);

#endif
