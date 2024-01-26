/*******************************************************************************
 * File:        Hbgs_issuer.cpp
 * Description: Code for the HBGS issuer class
 *
 * Author:      Chris Newton
 * Created:     Thursday 12 May 2022
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
#include <iosfwd>

#include "Io_utils.h"
#include "Hbgs_param.h"
#include "Mpc_node_address.h"
#include "Mfors_tree.h"
#include "Hbgs_issuer.h"

//#define DEBUG_ISSUER

const char Hbgs_issuer::seed_string_[]{
    "a5b10fa9d7afb373d72c353809826c4a5f6e9fad68d4a4c55ef304e3a035fa14"
};

Hbgs_issuer::Hbgs_issuer() noexcept
{
    issuer_name_ = "unset";

    if (!extract_master_seed()) {
        std::cerr << "Unable to extract the master seed\n";
        return;
    }

    get_param_set(get_picnic_parameter_set_id(), &paramset_);

    status_ = initialised;
}


Hbgs_issuer::Hbgs_issuer(std::string const &issuer_name) noexcept
  : Hbgs_issuer()
{
    issuer_name_ = issuer_name;

    if (calculate_public_key()) { status_ = key_set; }

#ifdef DEBUG_ISSUER
    std::cout << "Issuer: public key calculated for " << issuer_name_ << '\n';
#endif
}

Hbgs_issuer::Hbgs_issuer(
  std::string const &base_dir, std::string const &issuer_name) noexcept
  : Hbgs_issuer()
{
    std::string filename = make_issuer_filename(base_dir, issuer_name);
    std::ifstream is{ filename, std::ios::in };
    if (!is) {
        std::cerr << "Issuer: Unable to open and read the public key file: "
                  << filename << '\n';
        return;
    }

    is >> issuer_name_;
    if (issuer_name != issuer_name_) {
        std::cerr << "Issuer: incconsistent data - names mismatch\n";
        return;
    }

    if (!read_lowmc_state_bytes(is, (uint8_t *)master_seed_)) {
        std::cerr << "Issuer: error reading the master_seed_\n";
        return;
    }

    if (!read_lowmc_state_bytes(is, (uint8_t *)public_key_)) {
        std::cerr << "Issuer: error reading the public_key_\n";
        return;
    }

    status_ = key_set;

#ifdef DEBUG_ISSUER
    std::cout << "Issuer: public key data read for " << issuer_name_
              << std::endl;
#endif
}

bool Hbgs_issuer::save_data(std::string const &base_dir) const noexcept
{
    if (status_ != key_set) {
        std::cerr << "Issuer: save_data: issuer not correctly set up\n";
        return false;
    }

    std::string filename = make_issuer_filename(base_dir, issuer_name_);
    std::ofstream os{ filename, std::ios::out };
    if (!os) {
        std::cerr << "Issuer::save_data: unable to open the public key file "
                  << filename << '\n';
        return false;
    }

    os << issuer_name_ << '\n';
    print_lowmc_state_bytes(os, (uint8_t *)master_seed_);
    os << '\n';
    print_lowmc_state_bytes(os, (uint8_t *)public_key_);
    os << '\n';

    os.close();

#ifdef DEBUG_ISSUER
    std::cout << "Issuer: public key data written for " << issuer_name_
              << std::endl;
#endif

    return true;
}

bool Hbgs_issuer::calculate_public_key() noexcept
{
    G_tree_address gt_addr{ 0x00, 0x00 };

    Mfors_tree mf_tree(master_seed_, gt_addr, &paramset_);

    if (!mf_tree.calculate_leaves(nullptr)) {
        std::cerr << "Issuer: Mfors_tree: error calculating the leaves\n";
        return false;
    }

    if (!mf_tree.calculate_nodes()) {
        std::cerr << "Issuer: Mfors_tree: error calculating the nodes\n";
        return false;
    }

    if (!mf_tree.get_root(public_key_)) {
        std::cerr << "Issuer: Mfors_tree: unable to retrieve the root\n";
        return false;
    }

    return true;
}

bool Hbgs_issuer::extract_master_seed()
{
    static_assert(
      sizeof(seed_string_) >= 2 * Mpc_parameters::lowmc_state_bytes_);

    size_t str_index{ 0 };
    auto ms_bytes = (uint8_t *)master_seed_;
    std::string bstr(2, '\0');
    for (size_t i = 0; i < Mpc_parameters::lowmc_state_bytes_; ++i) {
        bstr[0] = seed_string_[str_index++];
        bstr[1] = seed_string_[str_index++];
        ms_bytes[i] = static_cast<uint8_t>(stoul(bstr, nullptr, 16));
    }
    zeroTrailingBits(ms_bytes, Mpc_parameters::lowmc_state_bits_);

#ifdef DEBUG_ISSUER
    std::cout << "Master seed: ";
    print_lowmc_state_words64(std::cout, master_seed_);
    std::cout << '\n';
#endif

    return true;
}

std::string make_issuer_filename(
  std::string const &base_dir, std::string const &issuer_name)
{
    std::string filename = make_filename(base_dir, issuer_name);

    std::ostringstream ostr;
    ostr << filename << '_' << Public_parameters::n_ << '.' << issuer_file_ext;

    return ostr.str();
}

std::string make_credential_filename(std::string const &base_dir,
  std::string const &issuer_name, std::string const &user_name)
{
    std::string filename = make_filename(base_dir, issuer_name);

    std::ostringstream ostr;
    ostr << filename << '_' << Public_parameters::n_ << '_'
         << 0 + Public_parameters::h_ << '_' << user_name << '.'
         << credential_file_ext;

    return ostr.str();
}
