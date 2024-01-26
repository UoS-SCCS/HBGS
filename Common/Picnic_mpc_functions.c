/*******************************************************************************
 * File:        Picnic_mpc_functions.c
 * Description: Picnic functions for MPC, adapted from the picnic code
 *
 * Author:      Chris Newton
 *
 * Created:     Monday 17 January 2022
 *
 * (C) Copyright 2022, University of Surrey.
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

#include <string.h>

#include "picnic.h"
#include "picnic_impl.h"
#include "picnic_types.h"

#include "Picnic_mpc_functions.h"


// Minor change to picnic commit function to allow for chaging size of aux bits
void commit_c(uint8_t *digest,
  uint8_t *seed,
  uint8_t *aux,
  uint8_t *salt,
  uint16_t t,
  uint16_t j,
  paramset_t *params)
{
    /* Compute C[t][j];  as digest = H(seed||[aux]) aux is optional */
    HashInstance ctx;

    HashInit(&ctx, params, HASH_PREFIX_NONE);
    HashUpdate(&ctx, seed, params->seedSizeBytes);
    if (aux != NULL) { HashUpdate(&ctx, aux, sizeof(aux)); }
    HashUpdate(&ctx, salt, params->saltSizeBytes);
    HashUpdateIntLE(&ctx, t);
    HashUpdateIntLE(&ctx, j);
    HashFinal(&ctx);
    HashSqueeze(&ctx, digest, params->digestSizeBytes);
}
