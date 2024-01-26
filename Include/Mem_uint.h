/*******************************************************************************
 * File:        Mem_uint.h
 * Description: Code for setting memory to uints and getting uints from
 *              memory
 *
 * Author:      Chris Newton
 *
 * Created:     Thursday 15 September 2022
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



#ifndef MEM_UINT_H
#define MEM_UINT_H

#include <limits>
#include <cstring>

#include "Hbgs_param.h"


template<typename U, typename = typename std::enable_if<
                       std::numeric_limits<U>::is_integer
                       && !std::numeric_limits<U>::is_signed>::type>
bool uint_to_mem(uint8_t *mem_addr, size_t len, U ui, bool store_big_endian)
{
    size_t ui_size = sizeof(U);
    if (ui_size > len) { return false; }
    std::memset(mem_addr, 0, len);
    size_t index{};
    for (size_t i = 0; i < ui_size; ++i) {
        index = store_big_endian ? ui_size - 1 - i : i;
        *(mem_addr + index) = (ui & 0xff);// NOLINT
        ui >>= 8;// NOLINT
    }

    return true;
}

template<typename U, typename = typename std::enable_if<
                       std::numeric_limits<U>::is_integer
                       && !std::numeric_limits<U>::is_signed>::type>
bool mem_to_uint(
  U &ival, uint8_t *mem_addr, size_t len, bool stored_as_big_endian)
{

    if (len > sizeof(U)) { return false; }
    size_t index{};
    index = stored_as_big_endian ? 0 : len - 1;
    ival = *(mem_addr + index);
    for (size_t i = 1; i < len; ++i) {
        index = stored_as_big_endian ? i : len - 1 - i;
        ival = (ival << 8) + *(mem_addr + index);// NOLINT
    }

    return true;
}


#endif
