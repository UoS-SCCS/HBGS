/*******************************************************************************
 * File:        Hbgs_param.h
 * Description: Parameters used for the HBGS routines
 *
 * Author:      Chris Newton
 * Created:     Tuesday 28 September 2021
 *
 * (C) Copyright 2021, University of Surrey. All rights reserved.
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



#ifndef HBGS_PARAM_H
#define HBGS_PARAM_H

#include <memory>
#include <utility>
#include <cassert>

#include "Hbgs_param.h"

#define assertm(exp, msg) assert(((void)msg, exp))

// Templates for Pow(base,n) - used for constexpr values
template<unsigned int base, unsigned int n> struct Pow
{
    enum size_t { Value = base * Pow<base, n - 1>::Value };
};

template<unsigned int base> struct Pow<base, 1>
{
    enum size_t { Value = base };
};

inline constexpr std::pair<uint32_t, uint32_t> calculate_tree_height(
  uint32_t nl, uint32_t q)
{
    uint32_t ht = 0;
    uint32_t n_leaves = 1;
    while (n_leaves < nl) {
        n_leaves *= q;
        ht++;
    }
    return std::make_pair(ht, n_leaves);
}

struct Public_parameters
{
    static constexpr uint16_t n_ = HBGS_N;
    static constexpr uint8_t q_alpha_ = HBGS_QA;
    static constexpr uint16_t q_ =
      Pow<2, HBGS_QA>::Value;// The number of children for each
                             // non-leaf node in the Group-tree
    static constexpr uint8_t h_ = HBGS_H;// The depth of the Group-tree
    static constexpr uint8_t d_ =
      HBGS_D;// The depth of the M-FORS Merkle sub-trees
    static constexpr uint16_t k_ =
      HBGS_K;// The number of Merkle sub-trees in an M-FORS tree

    static constexpr bool use_big_endian_{ false };
};

inline constexpr uint16_t rounds_per_path(uint16_t n_rounds)
{
    uint16_t rpp = n_rounds / Public_parameters::k_;

    // Adjust for test parameters with small round numbers
    return (rpp == 0) ? 1 : rpp;
}

struct Mpc_parameters
{
    static constexpr uint16_t lowmc_state_bits_ = HBGS_N;
    static constexpr uint16_t lowmc_state_bytes_ =
      (lowmc_state_bits_ + UINT16_C(7)) / UINT16_C(8);
    static constexpr uint16_t lowmc_state_words_ =
      (lowmc_state_bytes_ + UINT16_C(3)) / UINT16_C(4);
    static constexpr uint16_t lowmc_rounds_ = 4U;
    // ands bits gives the size of the aux and msgs for each LowMC. It assumes
    // a full set of S-boxes for each state
    static constexpr uint16_t lowmc_ands_bits_ =
      lowmc_rounds_ * lowmc_state_bits_;

    static constexpr uint16_t mpc_parties_ =
      16U;// mpc_parties must be divisible by 4 for the sha3 times4 calls
    static constexpr uint16_t mpc_rounds_ = HBGS_MPC_R;
    static constexpr uint16_t mpc_rounds_per_path_ =
      rounds_per_path(mpc_rounds_);

    static constexpr uint16_t opened_mpc_rounds_ = HBGS_MPC_O;

    static constexpr uint8_t picnic_parameter_set_ = PICNIC_PS;

    static constexpr uint16_t digest_size_bytes_ = HBGS_DS;

    // For our challenge lists we need one byte for each of the opened rounds, 4
    // bits as an offset for the round number and 4 bits for the party whose
    // tape is left unopened. A 4 bits offset corresponds to 16 rounds per path
    // Make the challenge hash the correct length
    static constexpr uint16_t lists_rounds_per_path_ = 16;
    static constexpr uint16_t challenge_hash_bytes_ =
      (mpc_rounds_per_path_ == lists_rounds_per_path_) ? opened_mpc_rounds_
                                                       : digest_size_bytes_;

    static constexpr uint16_t nonce_size_bytes_ = lowmc_state_bytes_;

    // At the moment
    //  paramset.seedSizeBytes, paramset.saltSizeBytes
    // are not included here
};

#endif
