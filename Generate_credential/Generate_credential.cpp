/*******************************************************************************
 * File:        Generate_credential.cpp
 * Description: Code to generate the credential for a SPHINCS+ tree
 *
 *
 * Author:      Chris Newton
 * Created:     Monday 9 May 2022
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



#include <cmath>
#include <cinttypes>
#include <cstring>
#include <thread>
#include <exception>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include "Io_utils.h"

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
}

#include "Hbgs_param.h"
#include "Picnic_mpc_functions.h"
#include "Lowmc64.h"
#include "Mpc_utils.h"
#include "Merkle_tree.h"
#include "Mfors_tree.h"
#include "Mpc_node_address.h"
#include "Mpc_parameters.h"
#include "Hash2_64.h"
#include "Hbgs_issuer.h"
#include "Generate_credential.h"

int generate_initial_data(
  Lowmc_state_words64_ptr hash1, Gt_index_type &gtree_index)
{
    if (picnic_random_bytes(
          (uint8_t *)hash1, Mpc_parameters::lowmc_state_bytes_)
        != 0) {
        std::cerr << "Failed to generate the test hash\n";
        return EXIT_FAILURE;
    }
    zeroTrailingBits((uint8_t *)hash1, Mpc_parameters::lowmc_state_bits_);

    if (Public_parameters::h_ == 0) {
        gtree_index = 0;
    } else {
        Gt_index_type max_index = static_cast<Gt_index_type>(
          std::pow(Public_parameters::q_, Public_parameters::h_) - 1);
        std::default_random_engine dre{};
        std::uniform_int_distribution<Gt_index_type> dist{ 0, max_index - 1 };
        gtree_index = dist(dre);
    }

    return EXIT_SUCCESS;
}

int generate_and_save_credential(std::string base_dir,
  std::string issuer_name,
  std::string user_name,
  bool check_paths)
{
    Lowmc_matrices::assign_lowmc_matrices();

    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);

    Hbgs_issuer issuer{ base_dir, issuer_name };
    if (issuer.status() != Hbgs_issuer::Status::key_set) {
        std::cerr << "Initialisation of the Issuer failed\n";
        return EXIT_FAILURE;
    }

    Lowmc_state_words64 hash1{ 0 };
    Gt_index_type gtree_index{ 0 };
    int ret = generate_initial_data(hash1, gtree_index);
    if (ret != 0) {
        std::cerr << "Test data generation failed\n";
        return EXIT_FAILURE;
    }

    std::string filename =
      make_credential_filename(base_dir, issuer_name, user_name);
    std::ofstream os{ filename, std::ios::out };
    if (!os) {
        std::cerr << "Unable to open the file " << filename << '\n';
        return EXIT_FAILURE;
    }

    Mpc_timing_data td;
    Mpc_timing_data td_full;

    print_lowmc_state_bytes(os, (uint8_t *)hash1);
    os << '\n';

    H2_data64 h2_data{};
    hash2_64(h2_data, hash1, &paramset);
    Signing_indices h2_indices;
    signing_indices_from_hash2(h2_indices, h2_data);
    print_signing_indices(os, h2_indices);

    G_tree_address gt_addr{ Public_parameters::h_, gtree_index };

    for (uint8_t l = Public_parameters::h_; l <= Public_parameters::h_; --l) {

        td.timer_.reset();

        std::cout << "level: " << 0 + l << " gt_addr row: " << 0 + gt_addr.row_
                  << " gt_addr index: " << gt_addr.index_ << '\n';
        Mfors_tree mf_tree(issuer.seed(), gt_addr, &paramset);

        if (!mf_tree.calculate_leaves(h2_indices)) {
            std::cerr << "Mfors_tree: error calculating the leaves\n";
            return EXIT_FAILURE;
        }

        if (!mf_tree.calculate_nodes()) {
            std::cerr << "Mfors_tree: error calculating the nodes\n";
            return EXIT_FAILURE;
        }

        Lowmc_state_words64 root{ 0 };

        if (!mf_tree.get_root(root)) {
            std::cerr << "Mfors_tree: unable to retrieve the root\n";
            return EXIT_FAILURE;
        }

        if (!mf_tree.calculate_top_authpaths()) {
            std::cerr << "Mfors_tree: failed to calcualte the top authpaths\n";
            return EXIT_FAILURE;
        }

        Mfors_authpath_const_ptr paths = mf_tree.get_authpaths();
        if (paths == nullptr) {
            std::cerr << "Mfors_tree: unable to retrieve the authpaths\n";
            return EXIT_FAILURE;
        }

        td.times_.emplace_back(
          Mpc_time_point{ "generate_top_tree_and_calculate_authpaths",
            static_cast<float>(td.timer_.get_duration() + 0.5f) });

        if (check_paths) {
            td.timer_.reset();

            if (!check_mfors_authpaths(root, paths, &paramset)) {
                std::cerr << "Authpaths check failed\n";
                return EXIT_FAILURE;
            }

            td.times_.emplace_back(Mpc_time_point{ "check_mfors_authpaths",
              static_cast<float>(td.timer_.get_duration() + 0.5f) });
        }

        td.timer_.reset();

        print_mfors_authpaths(os, paths);

        print_lowmc_state_bytes(os, (uint8_t *)root);
        os << '\n';

        td.times_.emplace_back(Mpc_time_point{ "write_mfors_authpath_data",
          static_cast<float>(td.timer_.get_duration() + 0.5f) });


        if (l > 0) {
            td.timer_.reset();

            hash2_64(h2_data, root, &paramset);
            signing_indices_from_hash2(h2_indices, h2_data);
            print_signing_indices(os, h2_indices);

            td.times_.emplace_back(
              Mpc_time_point{ "calculate_indices_from_hash",
                static_cast<float>(td.timer_.get_duration() + 0.5f) });

            td.timer_.reset();

            gt_addr.row_--;
            gt_addr.index_ /= Public_parameters::q_;

            td.times_.emplace_back(Mpc_time_point{ "adjust_G_tree_address",
              static_cast<float>(td.timer_.get_duration() + 0.5f) });
        }
    }

    os.close();

    td_full.times_.emplace_back(Mpc_time_point{ "generate_credential",
      static_cast<float>(td_full.timer_.get_duration() + 0.5f) });

    std::ostringstream ostr;
    ostr << issuer_name << '_' << user_name << ' ' << Public_parameters::n_
         << ' ' << 0 + Public_parameters::h_;

    for (auto const &tp : td.times_) {
        std::cout << ostr.str() << std::setw(42) << tp.type_ << ' ' << tp.time_
                  << '\n';
    }

    for (auto const &tp : td_full.times_) {
        std::cout << ostr.str() << std::setw(42) << tp.type_ << ' ' << tp.time_
                  << '\n';
    }

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        usage(std::cout, argv[0]);
        return EXIT_FAILURE;
    }

    std::string base_dir{ argv[1] };
    std::string issuer_name{ argv[2] };
    std::string user_name{ argv[3] };

    auto c = static_cast<char>(
      std::toupper(argv[4][0]));// Check the first character on;y
    if (c != 'T' && c != 'F') {
        std::cerr << "The options for 'check authpaths' are T or F\n";
        usage(std::cerr, argv[0]);
    }

    bool check_paths = (c == 'T');

    return generate_and_save_credential(
      base_dir, issuer_name, user_name, check_paths);
}

void usage(std::ostream &os, std::string program)
{
    os << green
       << "A program to generate and save the credential for a SPHINCS+ "
          "tree.\n"
       << normal << program
       << " <base dir> <issuer name> <user name> <check authpaths (T/F)>\n\n";
}
