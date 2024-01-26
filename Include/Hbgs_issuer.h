/*******************************************************************************
 * File:        Hbgs_issuer.h
 * Description: The HBGS issuer class
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



#ifndef HBGS_ISSUER_H
#define HBGS_ISSUER_H

#include <string>

#include "Hbgs_param.h"
#include "Lowmc64.h"

const std::string issuer_file_ext{ "pk" };
const std::string credential_file_ext{ "cred" };

class Hbgs_issuer
{
  public:
    enum Status { uninitialised, initialised, key_set };
    Hbgs_issuer() noexcept;
    // Initialise from scratch
    Hbgs_issuer(std::string const &name) noexcept;
    // Initialise from a file
    Hbgs_issuer(
      std::string const &base_dir, std::string const &filename) noexcept;
    bool save_data(std::string const &filename) const noexcept;
    Lowmc_state_words64_const_ptr public_key() const { return public_key_; }
    // For testing only - this is a secret!
    Lowmc_state_words64_const_ptr seed() const { return master_seed_; }

    std::string issuer_name() const { return issuer_name_; }
    Status status() const { return status_; }


  private:
    paramset_t paramset_;
    Status status_{ Status::uninitialised };
    std::string issuer_name_;
    Lowmc_state_words64 master_seed_{ 0 };
    Lowmc_state_words64 public_key_{ 0 };

    const static char seed_string_[];
    bool extract_master_seed();
    bool calculate_public_key() noexcept;
};

std::string make_issuer_filename(
  std::string const &base_dir, std::string const &issuer_name);

std::string make_credential_filename(std::string const &base_dir,
  std::string const &issuer_name, std::string const &user_name);

#endif
