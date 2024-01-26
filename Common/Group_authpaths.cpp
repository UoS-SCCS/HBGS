/*******************************************************************************
 * File:        Group_authpaths.h
 * Description: The Group tree authpaths for F_SPHINCS+
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



#include <string>
#include <iostream>
#include <cassert>

#include "Hbgs_param.h"
#include "Mpc_parameters.h"
#include "Merkle_tree.h"
#include "Mpc_node_address.h"
#include "Mfors_tree.h"
#include "Hbgs_issuer.h"
#include "Group_authpaths.h"

bool read_group_authpaths(Group_authpaths &g_paths, std::string const &base_dir,
  std::string const &name)
{
    std::string filename = make_filename(base_dir, name);
    filename = filename + '.' + credential_file_ext;
    std::ifstream is;
    is.open(filename.c_str(), std::ios::in);
    if (!is) {
        std::cerr << "Unable to open the authpath file: " << filename << '\n';
        return false;
    }

    size_t m = 0;
    for (size_t i = 0; i < Public_parameters::h_ + 1; ++i) {
        Mfors_tree_paths &mft_path = g_paths.mfors_tree_paths_[m];

        if (!read_lowmc_state_bytes(is, (uint8_t *)mft_path.input_hash_)) {
            std::cerr << "Error reading the input hash\n";
            is.close();
            return false;
        }

        if (!read_signing_indices(is, mft_path.indices_)) {
            is.close();
            return false;
        }

        if (!read_mfors_authpaths(is, mft_path.authpaths_)) {
            std::cerr << "Failed reading the authpath for i=" << i << '\n';
            is.close();
            return false;
        }
        m++;
    }
    if (!read_lowmc_state_bytes(is, (uint8_t *)g_paths.public_key_)) {
        std::cerr << "Failed reading the public key\n";
        is.close();
        return false;
    }

    is.close();

    return true;
}

bool check_group_authpaths(Group_authpaths &g_paths, paramset_t *params)
{
    for (size_t i = 0; i < Public_parameters::h_ + 1; ++i) {
        Mfors_tree_paths &mft_path = g_paths.mfors_tree_paths_[i];
        Lowmc_state_words64_const_ptr current_root =
          (i == Public_parameters::h_)
            ? g_paths.public_key_
            : g_paths.mfors_tree_paths_[i + 1].input_hash_;
        if (!check_mfors_authpaths(current_root, mft_path.authpaths_, params)) {
            std::cerr
              << "check_group_authpaths: check failed for MFORS tree paths["
              << i << "]\n";
            return false;
        }
    }

    return true;
}
