/*******************************************************************************
 * File:        Lowmc64.cpp
 * Description: SCalculation of LOWMC using uint64
 *
 * Author:      Chris Newton
 *
 * Created:     Wednesday 31 August 2022
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



#include "Io_utils.h"

#include <iostream>
#include <fstream>
#include <cstring>
#include <cmath>

#include "Picnic_mpc_functions.h"
#include "Mpc_utils.h"
#include "Lowmc32.h"
#include "Lowmc64.h"

void print_lowmc_state_words64(
  std::ostream &os, Lowmc_state_words64_const_ptr state_ptr) noexcept
{
    print_buffer(
      os, (uint8_t *)state_ptr, sizeof(*state_ptr) * lowmc_state_words64);
}

bool read_lowmc_state_words64(
  std::ifstream &is, Lowmc_state_words64_ptr state_ptr)
{
    state_ptr[lowmc_state_words64 - 1] = 0;

    return read_lowmc_state_bytes(is, reinterpret_cast<uint8_t *>(state_ptr));
}

void get_matrix_data(Matrix64 m64, uint32_t const *mdata)
{
    for (size_t i = 0; i < matrix_rows; ++i) {
        copy_lowmc_state_words_to_lowmc_state_words64(
          m64[i], mdata + i * words_per_row);
    }
}

Matrix64 Lowmc_matrices::km_[Matrix_numbers::nk_];
Matrix64 Lowmc_matrices::kmi_[Matrix_numbers::nki_];
Matrix64 Lowmc_matrices::lm_[Matrix_numbers::nl_];
Matrix64 Lowmc_matrices::lmi_[Matrix_numbers::nli_];
Lowmc_state_words64 Lowmc_matrices::rc_[Matrix_numbers::nr_];

void Lowmc_matrices::assign_lowmc_matrices()
{
    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);


    for (uint32_t i = 0; i < Matrix_numbers::nk_; ++i) {
        uint32_t const *mdata = KMatrix(i, &paramset);
        Matrix64 &m64 = km_[i];
        get_matrix_data(m64, mdata);
    }

    for (uint32_t i = 0; i < Matrix_numbers::nki_; ++i) {
        uint32_t const *mdata = KMatrixInv(i, &paramset);
        Matrix64 &m64 = kmi_[i];
        get_matrix_data(m64, mdata);
    }

    for (uint32_t i = 0; i < Matrix_numbers::nl_; ++i) {
        uint32_t const *mdata = LMatrix(i, &paramset);
        Matrix64 &m64 = lm_[i];
        get_matrix_data(m64, mdata);
    }

    for (uint32_t i = 0; i < Matrix_numbers::nli_; ++i) {
        uint32_t const *mdata = LMatrixInv(i, &paramset);
        Matrix64 &m64 = lmi_[i];
        get_matrix_data(m64, mdata);
    }

    for (uint32_t i = 0; i < Matrix_numbers::nr_; ++i) {
        uint32_t const *rdata = RConstant(i, &paramset);
        Lowmc_state_words64 &w64 = rc_[i];
        copy_lowmc_state_words_to_lowmc_state_words64(w64, rdata);
    }
}

void copy_lowmc_state_words_to_lowmc_state_words64(
  Lowmc_state_words64_ptr w64, Lowmc_state_words_const_ptr w32)
{
    w64[lowmc_state_words64 - 1] = 0;
    std::memcpy(w64, w32, Mpc_parameters::lowmc_state_bytes_);
}

void copy_lowmc_state_words64_to_lowmc_state_words(
  Lowmc_state_words_ptr w32, Lowmc_state_words64_const_ptr w64)
{
    w32[Mpc_parameters::lowmc_state_words_ - 1] = 0;
    std::memcpy(w32, w64, Mpc_parameters::lowmc_state_bytes_);
}

uint8_t parity64(uint64_t x)
{
    /* Compute parity of x using code from Section 5-2 of
     * H.S. Warren, *Hacker's Delight*, Pearson Education, 2003.
     * http://www.hackersdelight.org/hdcodetxt/parity.c.txt
     */
    uint64_t y = x ^ (x >> 1);
    y ^= (y >> 2);
    y ^= (y >> 4);
    y ^= (y >> 8);
    y ^= (y >> 16);
    y ^= (y >> 32);
    return y & 1;
}

void matrix_mul64(Lowmc_state_words64_ptr ciphertext,
  Lowmc_state_words64_const_ptr state,
  Matrix64 const &matrix)
{
    // Use temp to correctly handle the case when state = ciphertext
    uint64_t prod;
    Lowmc_state_words64 temp{ 0 };
    temp[lowmc_state_words64 - 1] = 0;

    for (uint32_t row = 0; row < matrix_rows; ++row) {
        prod = 0;
        for (uint64_t j = 0; j < words_per_row64; j++) {
            prod ^= (state[j] & matrix[row][j]);
        }

        setBit((uint8_t *)temp, row, parity64(prod));
    }
    ciphertext[lowmc_state_words64 - 1] = 0;
    memcpy(ciphertext, temp, Mpc_parameters::lowmc_state_bytes_);
}


void xor64(Lowmc_state_words64_ptr result, Lowmc_state_words64_const_ptr a,
  Lowmc_state_words64_const_ptr b)
{
    for (size_t i = 0; i < lowmc_state_words64; ++i) {
        result[i] = a[i] ^ b[i];
    }
}

void xor64(Lowmc_state_words64_ptr a, Lowmc_state_words64_const_ptr b)
{
    for (size_t i = 0; i < lowmc_state_words64; ++i) { a[i] ^= b[i]; }
}

void and64(Lowmc_state_words64_ptr a, Lowmc_state_words64_const_ptr b)
{
    for (size_t i = 0; i < lowmc_state_words64; ++i) { a[i] &= b[i]; }
}

void and64(Lowmc_state_words64_ptr result, Lowmc_state_words64_const_ptr a,
  Lowmc_state_words64_const_ptr b)
{
    for (size_t i = 0; i < lowmc_state_words64; ++i) {
        result[i] = a[i] & b[i];
    }
}

void lowmc64(Lowmc_state_words64_ptr ciphertext,
  Lowmc_state_words64_const_ptr key, Lowmc_state_words64_const_ptr plaintext,
  paramset_t *params) noexcept
{
    Lowmc_state_words64 round_key{ 0 };

    if (plaintext != ciphertext) {
        // ciphertext will hold the intermediate state
        std::memcpy(ciphertext, plaintext, Mpc_parameters::lowmc_state_bytes_);
    }

    matrix_mul64(round_key, key, Lowmc_matrices::km_[0]);
    xor64(ciphertext, round_key);
    for (uint32_t r = 1; r <= Mpc_parameters::lowmc_rounds_; r++) {
        matrix_mul64(round_key, key, Lowmc_matrices::km_[r]);
        substitution((uint32_t *)ciphertext, params);
        matrix_mul64(ciphertext, ciphertext, Lowmc_matrices::lm_[r - 1]);
        xor64(ciphertext, Lowmc_matrices::rc_[r - 1]);
        xor64(ciphertext, round_key);
    }
}

void hash1a64(Lowmc_state_words64_ptr hash, Lowmc_state_words64_const_ptr a,
  Lowmc_state_words64_const_ptr b, paramset_t *params) noexcept
{
    lowmc64(hash, a, b, params);
    xor64(hash, b);
}

void hash1b64(Lowmc_state_words64_ptr hash, Lowmc_state_words64_const_ptr a,
  Lowmc_state_words64_const_ptr b, Lowmc_state_words64_const_ptr c,
  paramset_t *params) noexcept
{
    Lowmc_state_words64 intermediate_state{ 0 };
    hash1a64(intermediate_state, a, b, params);

    lowmc64(hash, intermediate_state, c, params);

    xor64(hash, c);
}
