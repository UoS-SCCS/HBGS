/*******************************************************************************
 * File:        Hbgs_group_sign.cpp
 * Description: Code to test the SPHINCS+ tree's authpaths. It reads an
 *              authpaths file, amd signs using one of the tree's paths
 *
 * Author:      Chris Newton
 * Created:     Wednesday 27 July 2022
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
#include <random>
#include "Io_utils.h"


#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
}

#include "Hbgs_param.h"
#include "Picnic_mpc_functions.h"
#include "Mpc_lowmc.h"
#include "Mpc_utils.h"

#include "Mfors_tree.h"
#include "Group_authpaths.h"
#include "Mpc_node_address.h"
#include "Mpc_base_authpath.h"
#include "Mpc_top_authpath.h"
#include "Mpc_mfors_authpath.h"
#include "Mpc_parameters.h"
#include "Hbgs_issuer.h"
#include "Mpc_sign.h"
#include "Mpc_verify.h"
#include "Mpc_sign_mfors.h"
#include "Hbgs_group_sign.h"

//#define DEBUG_GROUP_SIGN

Mpc_group_sign::Mpc_group_sign(Group_authpaths_ptr group_paths_ptr) noexcept
  : group_paths_ptr_(group_paths_ptr)
{
    get_param_set(get_picnic_parameter_set_id(), &paramset_);
}

Tape_offset Mpc_group_sign::set_offsets(Tape_offset const &of) noexcept
{
    base_offset_ = of;

    for (size_t i = 0; i < n_trees_ - 1; ++i) {
        intermediate_root_mask_offset_[i] = base_offset_;
        base_offset_ += Mpc_parameters::lowmc_state_bits_;
    }
    // Create a dummy value to get the offset
    Tape_offset next_offset{ base_offset_ };
    Mpc_sign_mfors mf_sign(
      &group_paths_ptr_->mfors_tree_paths_[0], mpc_indices_);
    Tape_offset tree_delta = mf_sign.set_offsets(0);
    for (size_t tree = 0; tree < n_trees_; tree++) {
        tree_offsets_[tree] = next_offset;
        next_offset += tree_delta;
    }

    return next_offset + local_offset_bits_ + local_tape_bits_;
}

void Mpc_group_sign::compute_salt_and_root_seed(
  uint8_t *salt_and_root, size_t s_and_r_len, uint8_t const *nonce) noexcept
{
    HashInstance ctx;

    HashInit(&ctx, &paramset_, HASH_PREFIX_NONE);
    HashUpdate(&ctx, nonce, Mpc_parameters::nonce_size_bytes_);
    HashUpdate(&ctx, (uint8_t *)public_key_, paramset_.stateSizeBytes);
    HashUpdateIntLE(&ctx, (uint16_t)paramset_.stateSizeBits);
    HashFinal(&ctx);
    HashSqueeze(&ctx, salt_and_root, s_and_r_len);
}

void Mpc_group_sign::compute_aux_tape_sign(
  randomTape_t *tapes, Mpc_working_data &mpc_wd, size_t t) noexcept
{
    Mpc_proof_indices next_indices{ mpc_indices_ };

    for (size_t tree = 0; tree < n_trees_; tree++) {
        Lowmc_state_words64 root_mask{ 0 };
        if (tree != n_trees_ - 1) {
            get_mask_from_tapes(root_mask, &tapes[t],
              intermediate_root_mask_offset_[tree], &paramset_);
        }
        Mpc_sign_mfors mf_sign(
          &group_paths_ptr_->mfors_tree_paths_[tree], next_indices);
        mf_sign.set_offsets(tree_offsets_[tree]);

        mf_sign.compute_aux_tape_sign(tapes, root_mask, mpc_wd, t);

        next_indices = next_indices + mpc_indices_delta_;
    }
}

void Mpc_group_sign::compute_aux_tape_verify(randomTape_t *tapes,
  [[maybe_unused]] Signature_data const &sig_data, size_t t) noexcept
{
    Mpc_proof_indices next_indices{ mpc_indices_ };

    for (size_t tree = 0; tree < n_trees_; tree++) {
        Lowmc_state_words64 root_mask{ 0 };
        if (tree != n_trees_ - 1) {
            get_mask_from_tapes(root_mask, &tapes[t],
              intermediate_root_mask_offset_[tree], &paramset_);
        }

        Mpc_sign_mfors mf_sign(
          &group_paths_ptr_->mfors_tree_paths_[tree], next_indices);
        mf_sign.set_offsets(tree_offsets_[tree]);

        mf_sign.compute_aux_tape_verify(tapes, root_mask, sig_data, t);

        next_indices = next_indices + mpc_indices_delta_;
    }
}

void Mpc_group_sign::get_aux_bits(
  uint8_t *aux_bits, randomTape_t *tapes, size_t t) noexcept
{
    Tape_offset aux_pos{ 0 };
    Mpc_proof_indices next_indices{ mpc_indices_ };

    for (size_t tree = 0; tree < n_trees_; tree++) {
        Mpc_sign_mfors mf_sign(
          &group_paths_ptr_->mfors_tree_paths_[tree], next_indices);
        mf_sign.set_offsets(tree_offsets_[tree]);

        mf_sign.get_aux_bits(aux_bits, aux_pos, tapes, t);

        next_indices = next_indices + mpc_indices_delta_;
    }
}

void Mpc_group_sign::set_aux_bits(
  randomTape_t *tapes, Signature_data const &sig_data, size_t t) noexcept
{
    Tape_offset aux_pos{ 0 };
    Mpc_proof_indices next_indices{ mpc_indices_ };

    for (size_t tree = 0; tree < n_trees_; tree++) {
        Mpc_sign_mfors mf_sign(
          &group_paths_ptr_->mfors_tree_paths_[tree], next_indices);
        mf_sign.set_offsets(tree_offsets_[tree]);

        mf_sign.set_aux_bits(tapes, aux_pos, sig_data, t);

        next_indices = next_indices + mpc_indices_delta_;
    }
}

int Mpc_group_sign::mpc_simulate_sign(randomTape_t *tapes,
  Mpc_working_data &mpc_wd, shares_t *tmp_shares, size_t t) noexcept
{
    int rv{ EXIT_SUCCESS };
    Mpc_proof_indices next_indices{ mpc_indices_ };

    for (size_t tree = 0; tree < n_trees_; tree++) {

        Mpc_sign_mfors mf_sign(
          &group_paths_ptr_->mfors_tree_paths_[tree], next_indices);
        mf_sign.set_offsets(tree_offsets_[tree]);

        auto output = (Word *)mpc_wd.outputs_[next_indices.output_index_][t];

        rv = mf_sign.mpc_simulate_sign(tapes, output, mpc_wd, tmp_shares, t);
        if (rv != 0) {
            std::cerr << "mpc_simulate_sign failed for t=" << t << '\n';
            return EXIT_FAILURE;
        }

        next_indices = next_indices + mpc_indices_delta_;

#ifdef DEBUG_GROUP_SIGN
        if (t < 3) {
            if (tree == n_trees_ - 1) {
                std::cout << red;
            } else {
                std::cout << blue;
            }
            std::cout << "t=" << t << " tree= " << tree << " GSS output: ";
            print_lowmc_state_words64(std::cout, output);
            std::cout << "\n\n" << normal;
        }
#endif
    }
    return rv;
}

int Mpc_group_sign::mpc_simulate_and_verify(randomTape_t *tapes,
  Signature_data const &sig_data, msgs_t *msgs,
  Lowmc_state_words64_ptr expected_output_ptr, shares_t *tmp_shares,
  size_t t) noexcept
{
    int rv{ EXIT_SUCCESS };
    Mpc_proof_indices next_indices{ mpc_indices_ };
    for (size_t tree = 0; tree < n_trees_; tree++) {
        Mpc_sign_mfors mf_sign(
          &group_paths_ptr_->mfors_tree_paths_[tree], next_indices);
        mf_sign.set_offsets(tree_offsets_[tree]);

        Lowmc_state_words64 output{ 0 };
        rv = mf_sign.mpc_simulate_verify(
          tapes, sig_data, msgs, output, tmp_shares, t);
        if (rv != 0) {
            std::cerr << "mpc_simulate_verify failed for t=" << t << '\n';
            return EXIT_FAILURE;
        }

        auto test_output =
          (uint32_t *)sig_data.proofs_[t]->outputs_[next_indices.output_index_];

#ifdef DEBUG_GROUP_SIGN
        if (t < 3) {
            std::cout << "\nVerif output: ";
            print_lowmc_state_words64(std::cout, output);
            std::cout << "\n\n";
        }
#endif
        if (memcmp(test_output, output, paramset_.stateSizeBytes) != 0) {
            std::cerr << "Verification failed - the simulated outputs do "
                         "not match\n";
            return EXIT_FAILURE;
        }
        next_indices = next_indices + mpc_indices_delta_;
    }
    (void)expected_output_ptr;
    //    if (expected_output_ptr != nullptr// No output mask
    //        && memcmp(expected_output_ptr, output,
    //        paramset_.stateSizeBytes)
    //        != 0) { std::cerr << "Verification failed - the outputs do not
    //        match\n"; return EXIT_FAILURE;
    //    }

    return EXIT_SUCCESS;
}

void Mpc_group_sign::commit_v_sign(
  Commitment_data2 &c2, Mpc_working_data const &mpc_wd, size_t t)
{
    HashInstance ctx;
    msgs_t *msgs = &mpc_wd.msgs_[t];

    HashInit(&ctx, &paramset_, HASH_PREFIX_NONE);
    for (size_t i = 0; i < mpc_wd.mpc_inputs_.size(); ++i) {
        HashUpdate(&ctx, mpc_wd.mpc_inputs_[i][t], paramset_.stateSizeBytes);
    }
    for (size_t i = 0; i < paramset_.numMPCParties; i++) {
        auto msgs_size =
          static_cast<size_t>(numBytes(static_cast<uint32_t>(msgs->pos)));
        HashUpdate(&ctx, msgs->msgs[i], msgs_size);
    }
    HashFinal(&ctx);
    HashSqueeze(&ctx, c2.Cv.hashes[t], paramset_.digestSizeBytes);
}

void Mpc_group_sign::commit_v_verify(Commitment_data2 &c2,
  Signature_data const &sig_data, msgs_t const *msgs, size_t t)
{
    HashInstance ctx;

    HashInit(&ctx, &paramset_, HASH_PREFIX_NONE);
    for (size_t i = 0; i < sig_data.proofs_[t]->mpc_inputs_.size(); ++i) {
        HashUpdate(
          &ctx, sig_data.proofs_[t]->mpc_inputs_[i], paramset_.stateSizeBytes);
    }
    for (size_t i = 0; i < paramset_.numMPCParties; i++) {
        auto msgs_size =
          static_cast<size_t>(numBytes(static_cast<uint32_t>(msgs->pos)));
        HashUpdate(&ctx, msgs->msgs[i], msgs_size);
    }
    HashFinal(&ctx);
    HashSqueeze(&ctx, c2.Cv.hashes[t], paramset_.digestSizeBytes);
}

void Mpc_group_sign::calculate_hcp(uint8_t *challenge_hash,
  Signature_data const &sig_data, Commitment_data2 &cd2,
  uint8_t const *message_digest, uint8_t const *nonce) noexcept
{
    HashInstance ctx;

    HashInit(&ctx, &paramset_, HASH_PREFIX_NONE);
    for (size_t t = 0; t < paramset_.numMPCRounds; t++) {
        HashUpdate(&ctx, cd2.Ch.hashes[t], paramset_.digestSizeBytes);
    }

    HashUpdate(&ctx, cd2.treeCv->nodes[0], paramset_.digestSizeBytes);
    HashUpdate(&ctx, sig_data.mpc_pd_.salt_, paramset_.saltSizeBytes);
    HashUpdate(&ctx, (uint8_t *)public_key_, paramset_.stateSizeBytes);
    HashUpdate(&ctx, message_digest, Mpc_parameters::digest_size_bytes_);
    HashUpdate(&ctx, nonce, Mpc_parameters::nonce_size_bytes_);
    HashFinal(&ctx);
    HashSqueeze(&ctx, challenge_hash, Mpc_parameters::challenge_hash_bytes_);
}

void Mpc_group_sign::save_proof_data(
  Proof2 *proof, Mpc_working_data const &mpc_wd, size_t t)
{
    for (size_t i = 0; i < proof->mpc_inputs_.size(); ++i) {
        memcpy(proof->mpc_inputs_[i],
          mpc_wd.mpc_inputs_[i][t],
          paramset_.stateSizeBytes);
    }

    for (size_t i = 0; i < proof->outputs_.size(); ++i) {
        memcpy(
          proof->outputs_[i], mpc_wd.outputs_[i][t], paramset_.stateSizeBytes);
    }
    for (size_t i = 0; i < proof->inputs_.size(); ++i) {
        memcpy(
          proof->inputs_[i], mpc_wd.inputs_[i][t], paramset_.stateSizeBytes);
    }
}

//=============================================================================
// Now do the test

int test_group_authpaths(std::string const &base_dir,
  std::string const &credential_name, bool do_checks)
{
    Lowmc_matrices::assign_lowmc_matrices();

    Mpc_timing_data td;

    paramset_t paramset;
    get_param_set(get_picnic_parameter_set_id(), &paramset);

    Group_authpaths g_paths;
    if (!read_group_authpaths(g_paths, base_dir, credential_name)) {
        return EXIT_FAILURE;
    }

    if (do_checks) {
        if (!check_group_authpaths(g_paths, &paramset)) {
            std::cerr << "Group credential check failed\n";
            return EXIT_FAILURE;
        }
        std::cout << "Group credential checked OK\n";
    }

#ifdef DEBUG_GROUP_SIGN
    std::cout << "\nGroup authpaths data read "
              << ((do_checks) ? "and checked " : "") << "OK\n\n"
              << "Full MFORS authpaths read: " << Public_parameters::h_ + 1
              << '\n';

    std::cout << "           MFORS root: ";
    print_lowmc_state_words64(std::cout, g_paths.public_key_);
    std::cout << "\nOther tree roots:\n" << normal;
    for (size_t tree = 0; tree < g_paths.n_mfors_trees_ - 1; ++tree) {
        std::cout << "               tree " << tree << ": ";
        print_lowmc_state_words64(
          std::cout, g_paths.mfors_tree_paths_[tree + 1].input_hash_);
        std::cout << '\n';
    }
    std::cout << '\n';
#endif

    uint8_t nonce[Mpc_parameters::nonce_size_bytes_];
    if (picnic_random_bytes((uint8_t *)nonce, Mpc_parameters::nonce_size_bytes_)
        != 0) {
        std::cerr << "Failed to generate the nonce\n";
        return EXIT_FAILURE;
    }

    // A dummy digest for now
    uint8_t message_digest[Mpc_parameters::digest_size_bytes_];
    if (picnic_random_bytes(
          (uint8_t *)message_digest, Mpc_parameters::digest_size_bytes_)
        != 0) {
        std::cerr << "Failed to generate a message digest\n";
        return EXIT_FAILURE;
    }

#ifdef DEBUG_GROUP_SIGN
    std::cout << "Mfors_tree_test_h2: Mpc_param: \n";
    print_mpc_param(std::cout, Mpc_group_sign::mpc_param_);
    std::cout << '\n';

    std::cout << "Mpc_mfors_authpath: Mpc_param: \n";
    print_mpc_param(std::cout, Mpc_mfors_authpath::mpc_param_);
    std::cout << '\n';

    std::cout << "\nMpc_base_authpath: Mpc_param:\n";
    print_mpc_param(std::cout, Mpc_base_authpath::mpc_param_);
    std::cout << '\n';

    std::cout << "\nMpc_top_authpath: Mpc_param:\n";
    print_mpc_param(std::cout, Mpc_top_authpath::mpc_param_);
    std::cout << '\n';
#endif

    std::random_device
      rd;// Will be used to obtain a seed for the random number engine
    std::mt19937 gen(rd());// Standard mersenne_twister_engine seeded with rd()
    std::uniform_int_distribution<> distrib(0, Public_parameters::h_);

    Mpc_group_sign mft_test(&g_paths);

    Signature_data sig_data{ Mpc_group_sign::mpc_param_ };
    if (!sig_data.is_initialised_) {
        std::cerr << "Failed to initialise the signature data\n";
        return EXIT_FAILURE;
    }

    std::cout << "Signing ... " << std::flush;
    td.timer_.reset();
    int ret = generate_mpc_signature(mft_test, message_digest, nonce, sig_data);
    if (ret != EXIT_SUCCESS) {
        std::cerr << "Failed to create the signature\n ";
    }

    size_t max_signature_size =
      signature_size_estimate(Mpc_group_sign::mpc_param_, paramset);


#ifdef DEBUG_GROUP_SIGN
    std::cout << "\nMax signature length " << max_signature_size << "bytes\n ";
    std::cout << " Signing a " << Mpc_parameters::digest_size_bytes_
              << " byte message digest... " << std::flush;
#endif

    auto signature = static_cast<uint8_t *>(malloc(max_signature_size));
    if (signature == nullptr) {
        std::cerr << "Failed to allocate memory for the signature\n";
        return EXIT_FAILURE;
    }
    // Ensure that signature is freed
    std::unique_ptr<uint8_t, decltype(&::free)> signature_ptr(
      signature, ::free);

    size_t signature_len =
      sig_data.serialise_signature(signature, max_signature_size);
    if (signature_len == 0) {
        std::cerr << "Failed to serialize signature\n" << std::flush;
        return EXIT_FAILURE;
    }
    td.times_.emplace_back(Mpc_time_point{ "generate_signature",
      static_cast<float>(td.timer_.get_duration() + 0.5f) });

    std::cout << " success, signature is " << signature_len << " bytes\n";

    // signature_len has the exact number of bytes used
    if (signature_len < max_signature_size) {
        signature_ptr.release();
        uint8_t *newsig = (uint8_t *)realloc(signature, signature_len);
        if (newsig == NULL) {
            std::cerr << "Failed to re-size the signature\n ";
            // Not an error, we can continue with signature
        } else {
            signature = newsig;
            signature_ptr.reset(newsig);
        }
    }

    td.timer_.reset();

    Lowmc_state_words64_ptr expected_output_ptr = nullptr;
    ret = verify_mpc_signature(mft_test, signature, signature_len,
      message_digest, nonce, expected_output_ptr);

    td.times_.emplace_back(Mpc_time_point{ "verify_signature",
      static_cast<float>(td.timer_.get_duration() + 0.5f) });

    if (ret != EXIT_SUCCESS) {
        std::cerr << "\nSignature verification failed\n";
        return EXIT_FAILURE;
    }

    std::ostringstream ostr;
    ostr << credential_name << ' ' << Public_parameters::n_ << ' '
         << 0 + Public_parameters::h_;


    std::cout << ostr.str() << std::setw(19) << "signature_size" << ' '
              << signature_len << '\n';


    for (auto const &tp : td.times_) {
        std::cout << ostr.str() << std::setw(19) << tp.type_ << " " << tp.time_
                  << '\n';
    }

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        usage(std::cout, argv[0]);
        return EXIT_FAILURE;
    }

    std::string base_dir{ argv[1] };
    std::string credential_name{ argv[2] };

    if (!model_parameters_check_ok()) {
        std::cerr << "Inconsistent model parameters. Model parameters are:\n";
        print_hbgs_parameters(std::cerr);
        std::cerr << "Picnic parameters are:\n";
        print_picnic_parameters(std::cerr);
        std::cerr << '\n';
        return EXIT_FAILURE;
    }

    auto c = static_cast<char>(
      std::toupper(argv[3][0]));// Check the first character on;y
    if (c != 'T' && c != 'F') {
        std::cerr << "The options for 'do_checks' are T or F\n";
        usage(std::cerr, argv[0]);
    }

    bool do_checks = (c == 'T');

    return test_group_authpaths(base_dir, credential_name, do_checks);
}

void usage(std::ostream &os, std::string program)
{
    os << green
       << "A program to read the Group credential and generate a "
          "signature.\n";
    os << normal << "    " << program
       << " <base dir> <filename> <do_checks (T/F)>\n";
    os << "<do_checks> determines whether the credential is checked prior to "
          "signing.\n\n ";
}
