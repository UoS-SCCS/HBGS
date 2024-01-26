/*******************************************************************************
 * File:        Group_authpaths.h
 * Description: The Group tree authpaths for F_SPHICS+
 *
 * Author:      Chris Newton
 * Created:     Friday 22 July 2022
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



#ifndef GROUP_AUTHPATHS_H
#define GROUP_AUTHPATHS_H

#include <string>
#include <iostream>
#include <cassert>

#include "Hbgs_param.h"
#include "Mpc_parameters.h"
#include "Lowmc64.h"
#include "Mfors_tree.h"

struct Group_authpaths
{

    constexpr static size_t n_mfors_trees_ = Public_parameters::h_ + 1;
    Lowmc_state_words64 public_key_{ 0 };
    Mfors_tree_paths mfors_tree_paths_[n_mfors_trees_];
};

using Group_authpaths_ptr = Group_authpaths *;
using Group_authpaths_const_ptr = Group_authpaths const *;

bool read_group_authpaths(Group_authpaths &g_paths, std::string const &base_dir,
  std::string const &name);

bool check_group_authpaths(Group_authpaths &g_paths, paramset_t *params);

#endif
