/*******************************************************************************
 * File:        Picnic_mpc_functions.h
 * Description: Picnic functions for MPC, adapted from the picnic code
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



#ifndef PICNIC_MPC_FUNCTIONS_H
#define PICNIC_MPC_FUNCTIONS_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "picnic.h"
#include "picnic_types.h"
#include "picnic_impl.h"
#include "hash.h"
#include "tree.h"
#include "lowmc_constants.h"

// From picnic3_impl.c (duplicate definitons are allowed)
#define MAX_AUX_BYTES (((LOWMC_MAX_AND_GATES + LOWMC_MAX_KEY_BITS)) / 8 + 1)

// Defined in picnic.c - not used now we setup our own
int get_param_set(picnic_params_t picnicParams, paramset_t *paramset);
// Defined in picnic.c- not used now
int is_valid_params(picnic_params_t params);

// Defined in picnic3_impl.c (removed the static label);
void substitution(uint32_t *state, paramset_t *params);
// Defined in picnic3_impl.c (removed the static label);
void tapesToWords(shares_t *shares, randomTape_t *tapes);
// Defined in picnic3_impl.c (removed the static label)
void tapesToParityBits(
  uint32_t *output, size_t outputBitLen, randomTape_t *tapes);
// Defined in picnic3_impl.c (removed the static label)
int contains(uint16_t *list, size_t len, size_t value);
// Defined in picnic3_impl.c (removed the static label)
int indexOf(uint16_t *list, size_t len, size_t value);
// Defined in picnic3_impl.c (removed the static label)
uint16_t *getMissingLeavesList(uint16_t *challengeC, paramset_t *params);
// Defined in picnic3_impl.c (removed the static label)
void commit_h(uint8_t *digest, commitments_t *C, paramset_t *params);
// Defined in picnic3_impl.c (removed the static label)
void commit_v(
  uint8_t *digest, uint8_t *input, msgs_t *msgs, paramset_t *params);
// Defined in picnic3_impl.c (removed the static label)
void computeSaltAndRootSeed(uint8_t *saltAndRoot,
  size_t saltAndRootLength,
  uint32_t *privateKey,
  uint32_t *pubKey,
  uint32_t *plaintext,
  const uint8_t *message,
  size_t messageByteLength,
  paramset_t *params);
// Defined in picnic3_impl.c (removed the static label)
void expandChallengeHash(uint8_t *challengeHash,
  uint16_t *challengeC,
  uint16_t *challengeP,
  paramset_t *params);
// Defined in picnic3_impl.c (removed the static label)
void aux_mpc_sbox(const uint32_t *in,
  const uint32_t *out,
  randomTape_t *tapes,
  paramset_t *params);
// Defined in picnic3_impl.c (removed the static label)
void mpc_sbox(uint32_t *state,
  shares_t *state_masks,
  randomTape_t *tapes,
  msgs_t *msgs,
  paramset_t *params);

// Defined in picnic3_impl.c (removed the static label)
void HCP(uint8_t *challengeHash,
  uint16_t *challengeC,
  uint16_t *challengeP,
  commitments_t *Ch,
  uint8_t *hCv,
  uint8_t *salt,
  const uint32_t *pubKey,
  const uint32_t *plaintext,
  const uint8_t *message,
  size_t messageByteLength,
  paramset_t *params);

// Defined in picnic3_impl.c (removed the static label)
void aux_mpc_AND(uint8_t mask_a,
  uint8_t mask_b,
  uint8_t fresh_output_mask,
  randomTape_t *tapes,
  paramset_t *params);

// Defined in picnic3_impl.c (removed the static label)
uint8_t mpc_AND(uint8_t a,
  uint8_t b,
  uint16_t mask_a,
  uint16_t mask_b,
  randomTape_t *tapes,
  msgs_t *msgs,
  paramset_t *params);

// Defined in picnic3_impl.c (removed the static label)
uint16_t tapesToWord(randomTape_t *tapes);

// Defined in picnic3_impl.c (removed the static label)
uint16_t parity16(uint16_t x);

// Minor change to picnic function to allow for chaging size of aux bits
void commit_c(uint8_t *digest,
  uint8_t *seed,
  uint8_t *aux,
  uint8_t *salt,
  uint16_t t,
  uint16_t j,
  paramset_t *params);


#ifdef __cplusplus
}
#endif

#endif
