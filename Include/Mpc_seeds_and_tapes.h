/*******************************************************************************
 * File:        Mpc_seeds_and_tapes.h
 * Description: Utilities used for MPC seeds and tapes
 *
 * Author:      Chris Newton
 *
 * Created:     Monday 21 February 2022
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



#ifndef MPC_SEEDS_TAPES_H
#define MPC_SEEDS_TAPES_H

#include <iostream>
#include <cmath>

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "tree.h"
}

class Signing_seeds_and_tapes
{
  public:
    Signing_seeds_and_tapes() = delete;
    Signing_seeds_and_tapes(
      size_t tape_size_bytes, uint8_t *salt, tree_t *iSeedsTree) noexcept;
    ~Signing_seeds_and_tapes();

    bool is_initialised{ false };
    tree_t *iSeedsTree_{ nullptr };
    randomTape_t *tapes_{ nullptr };
    tree_t **seeds_{ nullptr };

  private:
    uint8_t **iSeeds_{ nullptr };
};

class Verification_seeds_and_tapes
{
  public:
    Verification_seeds_and_tapes() = delete;
    Verification_seeds_and_tapes(
      size_t tape_size_bytes, Signature_data const &sig_data) noexcept;
    ~Verification_seeds_and_tapes();

    bool is_initialised_{ false };
    tree_t *iSeedsTree_{ nullptr };
    randomTape_t *tapes_{ nullptr };
    tree_t **seeds_{ nullptr };

  private:
    uint8_t **iSeeds_{ nullptr };
};

using Shares_ptr = std::unique_ptr<shares_t, decltype(&::freeShares)>;

using Tree_ptr = std::unique_ptr<tree_t, decltype(&::freeTree)>;

#endif
