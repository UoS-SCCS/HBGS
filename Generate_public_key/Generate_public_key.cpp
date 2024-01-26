/*******************************************************************************
 * File:        Generate-public_key.cpp
 * Description: Code to test the issuer class generation and saving of
 *				public key.
 *
 * Author:      Chris Newton
 * Created:     Monday 18 July 2022
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
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include "Io_utils.h"

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
}

#include "Hbgs_param.h"
#include "Picnic_mpc_functions.h"
#include "Mpc_lowmc64.h"
#include "Mpc_utils.h"
#include "Merkle_tree.h"
#include "Mfors_tree.h"
#include "Mpc_node_address.h"
#include "Mpc_parameters.h"
#include "Hbgs_issuer.h"
#include "Generate_public_key.h"

int generate_public_key(
  std::string const &base_dir, std::string const &issuer_name)
{
    Lowmc_matrices::assign_lowmc_matrices();

    Mpc_timing_data td;

    Hbgs_issuer issuer{ issuer_name };
    if (issuer.status() != Hbgs_issuer::Status::key_set) {
        std::cerr << "Initialisation of the Issuer failed\n";
        return EXIT_FAILURE;
    }

    td.times_.emplace_back(Mpc_time_point{ "calculate_public_key",
      static_cast<float>(td.timer_.get_duration() + 0.5f) });

    td.timer_.reset();

    issuer.save_data(base_dir);

    td.times_.emplace_back(Mpc_time_point{
      "save_data", static_cast<float>(td.timer_.get_duration() + 0.5f) });

    td.timer_.reset();

    Hbgs_issuer issuer2{ base_dir, issuer_name };
    if (issuer2.status() != Hbgs_issuer::Status::key_set) {
        std::cerr << "Initialisation of the Issuer from the file failed\n";
        return EXIT_FAILURE;
    }

    td.times_.emplace_back(Mpc_time_point{ "construct_from_file",
      static_cast<float>(td.timer_.get_duration() + 0.5f) });

    if (std::memcmp(issuer.public_key(), issuer2.public_key(),
          Mpc_parameters::lowmc_state_bytes_)
        != 0) {
        std::cerr << "Issuer keys do not match\n";
        return EXIT_FAILURE;
    }

    std::ostringstream ostr;
    ostr << issuer_name << ' ' << Public_parameters::n_ << " x";

    for (auto const &tp : td.times_) {
        std::cout << ostr.str() << std::setw(21) << tp.type_ << " " << tp.time_
                  << '\n';
    }

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        usage(std::cout, argv[0]);
        return EXIT_FAILURE;
    }

    std::string base_dir{ argv[1] };
    std::string issuer_name{ argv[2] };

    return generate_public_key(base_dir, issuer_name);
}

void usage(std::ostream &os, std::string const& program)
{
    os << green
       << "A program to test the Issuer's generation and saving of the public "
          "key.\n"
       << normal << program << " <base dir> <issuer name>\n\n";
}
