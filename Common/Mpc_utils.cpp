/*******************************************************************************
 * File:        Mpc_utils.cpp
 * Description: Structures and utilities used for MPC
 *
 * Author:      Chris Newton
 *
 * Created:     Monday 17 January 2022
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



#include <iostream>
#include <string>
#include <cstring>
#include <cmath>
#include "Io_utils.h"

#include "picnic.h"
extern "C" {
#include "picnic_types.h"
#include "picnic3_impl.h"
#include "kdf_shake.h"
}

#include "Picnic_mpc_functions.h"
#include "Hbgs_param.h"
#include "Lowmc64.h"
#include "Mpc_utils.h"

picnic_params_t get_picnic_parameter_set_id()
{
    auto ps =
      static_cast<picnic_params_t>(Mpc_parameters::picnic_parameter_set_);
    if (ps < Picnic3_L1 || ps > Picnic3_L5t) { return PARAMETER_SET_INVALID; }
    return ps;
}

bool model_parameters_check_ok()
{
    paramset_t paramset;
    int ret = get_param_set(get_picnic_parameter_set_id(), &paramset);
    if (ret != EXIT_SUCCESS) {
        std::cout << "Failed to retrieve the picnic parameter set\n";
        return false;
    }
    bool parameters_ok{ true };
    if (paramset.stateSizeBits != HBGS_N) {
        std::cerr << "Inconsistent number of bits (n)\n";
        return false;
    }
    if (paramset.stateSizeBytes != Lowmc_parameters::lowmc_state_bytes_) {
        std::cerr << "Inconsistent lowmc_state_bytes\n";
        return false;
    }
    if (paramset.stateSizeWords != Lowmc_parameters::lowmc_state_words_) {
        std::cerr << "Inconsistent lowmc_state_words\n";
        return false;
    }
    if (paramset.numRounds != Lowmc_parameters::lowmc_rounds_) {
        std::cerr << "Inconsistent lowmc_rounds\n";
        return false;
    }
    if (paramset.andSizeBytes != (Lowmc_parameters::lowmc_ands_bits_ + 7U) / 8U) {
        std::cerr << "Inconsistent lowmc_aux_bytes\n";
        return false;
    }
    if (paramset.numMPCParties != Mpc_parameters::mpc_parties_) {
        std::cerr << "Inconsistent number of parties\n";
        return false;
    }
    if (paramset.digestSizeBytes != Mpc_parameters::digest_size_bytes_) {
        std::cerr << "Inconsistent digest sizes\n";
        return false;
    }
    if (paramset.numMPCRounds != Mpc_parameters::mpc_rounds_) {
        std::cerr << "Inconsistent number of MPC rounds\n";
        return false;
    }
    if (paramset.numOpenedRounds != Mpc_parameters::opened_mpc_rounds_) {
        std::cerr << "Inconsistent number of opened MPC rounds\n";
        return false;
    }

    return parameters_ok;
}

void print_picnic_parameters(std::ostream &os)
{
    paramset_t paramset;
    [[maybe_unused]] int ret =
      get_param_set(get_picnic_parameter_set_id(), &paramset);
    os << "The picnic parameter set used, "
       << picnic_get_param_name(get_picnic_parameter_set_id()) << ", has\n";
    os << green << "\t  stateSizeBits: " << paramset.stateSizeBits << '\n'
       << "\t stateSizeBytes: " << paramset.stateSizeBytes << '\n'
       << "\t stateSizeWords: " << paramset.stateSizeWords << '\n'
       << "\t numLowMCRounds: " << paramset.numRounds << '\n'
       << "\t numLowMCSboxes: " << paramset.numSboxes << '\n'
       << "\t   andSizeBytes: " << paramset.andSizeBytes << '\n'
       << "\t  numMPCParties: " << paramset.numMPCParties << '\n'
       << "\t   numMPCRounds: " << paramset.numMPCRounds << '\n'
       << "\tnumOpenedRounds: " << paramset.numOpenedRounds << '\n'
       << "\t  seedSizeBytes: " << paramset.seedSizeBytes << '\n'
       << "\t  saltSizeBytes: " << paramset.saltSizeBytes << '\n'
       << "\tdigestSizeBytes: " << paramset.digestSizeBytes << '\n'
       << normal;
}

void print_hbgs_parameters(std::ostream &os)
{
    os << green << "The HBGS parameters are\n"
       << "\t                 n: " << Tree_parameters::n_ << '\n'
       << "\t           q_alpha: " << 0 + Tree_parameters::q_alpha_ << '\n'
       << "\t                 q: " << Tree_parameters::q_ << '\n'
       << "\t                 h: " << 0 + Tree_parameters::h_ << '\n'
       << "\t                 d: " << 0 + Tree_parameters::d_ << '\n'
       << "\t                 k: " << Tree_parameters::k_ << '\n';

    os << "\nThe LowMC parameters are\n"
       << "\t  lowmc_state_bits: " << Lowmc_parameters::lowmc_state_bits_ << '\n'
       << "\t lowmc_state_bytes: " << Lowmc_parameters::lowmc_state_bytes_ << '\n'
       << "\t lowmc_state_words: " << Lowmc_parameters::lowmc_state_words_ << '\n'
       << "\t      lowmc_rounds: " << Lowmc_parameters::lowmc_rounds_ << '\n'
       << "\t  lowmc_ands_bytes: "
       << (Lowmc_parameters::lowmc_ands_bits_ + 7U) / 8U << '\n';

    os << "\nThe MPC parameters are\n"
       << "\t       mpc_parties: " << Mpc_parameters::mpc_parties_ << '\n'
       << "\t        mpc_rounds: " << Mpc_parameters::mpc_rounds_ << '\n'
       << "\t opened_mpc_rounds: " << Mpc_parameters::opened_mpc_rounds_ << '\n'
       << normal;
}

void print_random_tapes(std::ostream &os, randomTape_t *tapes, size_t tape_size)
{
    for (size_t i = 0; i < tapes->nTapes; ++i) {
        os << i << '\t' << (void *)tapes->tape[i] << '\t';
        print_buffer(os, tapes->tape[i], tape_size);
        os << '\n';
    }
}

void print_mpc_param(std::ostream &os, Mpc_param const &mpc_param)
{
    os << " aux_size_bits: " << mpc_param.aux_size_bits_ << '\n';
    os << "aux_size_bytes: " << mpc_param.aux_size_bytes_ << '\n';
    os << "  n_mpc_inputs: " << mpc_param.n_mpc_inputs_ << '\n';
    os << "      n_inputs: " << mpc_param.n_inputs_ << '\n';
    os << "     n_outputs: " << mpc_param.n_outputs_ << std::endl;
}

void print_proof_indices(std::ostream &os, Mpc_proof_indices const &indices)
{
    os << "    input index: " << indices.input_index_ << '\n';
    os << "mpc_input index: " << indices.mpc_input_index_ << '\n';
    os << "   output index: " << indices.output_index_ << '\n';
}

void allocate_random_tapes(
  randomTape_t *tape, size_t tape_size_bytes, paramset_t *params)
{
    tape->nTapes = params->numMPCParties;
    tape->tape =
      static_cast<uint8_t **>(malloc(tape->nTapes * sizeof(uint8_t *)));
    auto slab =
      static_cast<uint8_t *>(calloc(1, tape->nTapes * tape_size_bytes));
    for (uint8_t i = 0; i < tape->nTapes; i++) {
        tape->tape[i] = slab;
        slab += tape_size_bytes;
    }
    tape->pos = 0;
}

void create_random_tapes(randomTape_t *tapes,
  uint8_t **seeds,
  uint8_t *salt,
  uint16_t t,
  size_t tape_size_bytes,
  paramset_t *params)
{
    HashInstance ctx;

    allocate_random_tapes(tapes, tape_size_bytes, params);
    for (uint16_t i = 0; i < params->numMPCParties; i++) {
        HashInit(&ctx, params, HASH_PREFIX_NONE);
        HashUpdate(&ctx, seeds[i], params->seedSizeBytes);
        HashUpdate(&ctx, salt, params->saltSizeBytes);
        HashUpdateIntLE(&ctx, t);
        HashUpdateIntLE(&ctx, i);
        HashFinal(&ctx);

        HashSqueeze(&ctx, tapes->tape[i], tape_size_bytes);
    }
}


void create_random_tapes_times4(randomTape_t *tapes,
  uint8_t **seeds,
  uint8_t *salt,
  size_t t,
  size_t tape_size_bytes,
  paramset_t *params)
{

    hash_context_x4 ctx;

    allocate_random_tapes(tapes, tape_size_bytes, params);
    assertm(params->numMPCParties % 4 == 0,
      "create_random_tapes_times4: numMPCParties must be a multiple of 4");
    for (size_t i = 0; i < params->numMPCParties; i += 4) {
        hash_init_x4(&ctx, params->digestSizeBytes);

        const uint8_t *seeds_ptr[4] = { seeds[i], seeds[i + 1], seeds[i + 2],
            seeds[i + 3] };
        hash_update_x4(&ctx, seeds_ptr, params->seedSizeBytes);
        const uint8_t *salt_ptr[4] = { salt, salt, salt, salt };
        hash_update_x4(&ctx, salt_ptr, params->saltSizeBytes);
        hash_update_x4_uint16_le(&ctx, static_cast<uint16_t>(t));
        const uint16_t i_arr[4] = { static_cast<uint16_t>(i + 0),
            static_cast<uint16_t>(i + 1), static_cast<uint16_t>(i + 2),
            static_cast<uint16_t>(i + 3) };
        hash_update_x4_uint16s_le(&ctx, i_arr);
        hash_final_x4(&ctx);

        uint8_t *out_ptr[4] = { tapes->tape[i], tapes->tape[i + 1],
            tapes->tape[i + 2], tapes->tape[i + 3] };
        hash_squeeze_x4(&ctx, out_ptr, tape_size_bytes);
    }
}

// Retrieve a mask from the given tape and offset. Assumes the memory is already
// correctly allocated. Note, the tape position moves on!
void get_mask_from_tapes(
  uint32_t *mask, randomTape_t *tapes, uint32_t offset, paramset_t *params)
{
    tapes->pos = offset;
    mask[params->stateSizeWords - 1] = 0;
    tapesToParityBits(mask, params->stateSizeBits, tapes);
}

void get_mask_from_tapes(
  Word *mask, randomTape_t *tapes, uint32_t offset, paramset_t *params)
{
    tapes->pos = offset;
    mask[lowmc_state_words64 - 1] = 0;
    tapesToParityBits((uint32_t *)mask, params->stateSizeBits, tapes);
}

size_t hbgs_signature_size(paramset_t *params, size_t proof_data_size)
{
    // Picnic3 parameter sets only
    size_t u = params->numOpenedRounds;
    size_t T = params->numMPCRounds;
    size_t numTreeValues =
      u * ceil_log2((uint32_t)((T + (u - 1)) / u));// u*ceil(log2(ceil(T/u)))

    size_t proofSize =
      params->seedSizeBytes
        * ceil_log2(params->numMPCParties)// Info to recompute seeds
      + params->digestSizeBytes// size of commitment of unopened party
      + proof_data_size;// aux, masked_inputs, broadcast messages,
                        // masked_outputs, masked_plaintext, ...

    size_t signatureSize =
      params->saltSizeBytes// salt
      + params->digestSizeBytes// challenge hash
      + numTreeValues * params->seedSizeBytes// iSeed info
      + numTreeValues
          * params->digestSizeBytes// commitment opening info for views
      + proofSize * u;// one proof per challenged (opened) execution
    return signatureSize;
}

msgs_t *allocate_msgs(paramset_t *params, size_t msgs_size)
{
    auto msgs =
      static_cast<msgs_t *>(malloc(params->numMPCRounds * sizeof(msgs_t)));
    auto slab = static_cast<uint8_t *>(calloc(1,
      params->numMPCRounds
        * (params->numMPCParties * msgs_size
           + params->numMPCParties * sizeof(uint8_t *))));

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        msgs[i].pos = 0;
        msgs[i].unopened = -1;
        msgs[i].msgs = (uint8_t **)slab;
        slab += params->numMPCParties * sizeof(uint8_t *);

        for (uint32_t j = 0; j < params->numMPCParties; j++) {
            msgs[i].msgs[j] = slab;
            slab += msgs_size;
        }
    }

    return msgs;
}

void free_msgs(msgs_t *msgs)
{
    free(msgs[0].msgs);
    free(msgs);
}

void calculate_challenge_lists(uint8_t *challenge_hash, uint16_t *challengeC,
  uint16_t *challengeP, paramset_t *params)
{
    if (Mpc_parameters::mpc_rounds_per_path_
        != Mpc_parameters::lists_rounds_per_path_) {
        expandChallengeHash(challenge_hash, challengeC, challengeP, params);
        return;
    }

    calcualte_challenge_lists16(challenge_hash, challengeC, challengeP);
}

void calcualte_challenge_lists16(
  uint8_t *challenge_hash, uint16_t *challengeC, uint16_t *challengeP)
{
    assertm(Mpc_parameters::opened_mpc_rounds_ == Tree_parameters::k_,
      "calculate_challenge_lists16: inconsistent values for k_ and "
      "opened_mpc_rounds_");
    for (uint16_t i = 0; i < Tree_parameters::k_; ++i) {
        challengeC[i] =
          static_cast<uint16_t>(i * Mpc_parameters::mpc_rounds_per_path_
                                + (challenge_hash[i] & 0x0f));
        challengeP[i] = (challenge_hash[i] & 0xf0) >> 4;
        // std::cout << i << " challengeC: " << challengeC[i] << " challengeP "
        //          << challengeP[i] << '\n';
    }
}
