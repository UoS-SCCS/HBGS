# HBGS_code

Source code for a test implementation of the group signature scheme from symmetric primitives described in:

Sphinx-in-the-Head: Group Signatures from Symmetric Primitives
Liqun Chen, Changyu Dong, Christopher J. P. Newton, Yalan Wang

Publiched in ACM Transactions on Privacy and Security (doi.acm.org?doi=3638763).

## Description
This project is a test implementation of the symmetric setting group signature
scheme. It is based on the SPHINCS+ signature scheme extended to use 
MPC-in-the_Head. The code uses some of the reference picnic3 code from:

https://github.com/Microsoft/Picnic.

There are separate executables for each value of: the number of bits in the
LowMC state (n) and the height of the FSPHINCS+ tree (h). The executables are
built using cmake, which is set to allow executables for n=129 or n=255, with
h=1, h=2 , h=4 or h=6 to be built.

## Installation
Install the code files in a directory. Change to this directory.

Change to the HBGS_picnic directory and make the picnic libraries

   cd HBGS_picnic
   make

Return to the code directory and create a build directory:

  mkdir build

Change to this directory and enter

  cmake ..

Then you can use 

  ccmake ..

to select which executable to build and then use make to build the executables.
For a given choice of parameters, the executables that will be built are:

  generate_public_key_<nnn>,

  generate_credential_<nnn>_<h> and

  hbgs_group_sign_<nnn>_<h>.  

Where <nnn> is 129, or 255 and <h> is 1, 2, 4 or 6. The executables will be
found in <code directory>/bin

## Usage

Start by creating an Issuer's public key, in the code directory enter:

  bin/generate_public_key_<nnn> <base dir> <issuer name>

Where <base_dir> is the directory where the results are to be stored and
<issuer name> is a name assigned by the Issuer. This generates a key file

  <base dir>>/<issuer name>_<nnn>.pk.

The next stage is to generate a credential for a User:

  bin/generate_credential_<nnn>_<h> <base dir> <issuer name> <user name> <T/F>

The last option, T  or F, fixes whether the credential that is generated should
also be checked before writing to the file. This generates a credential file

  <base dir>/<issuer name>_<nnn>_<h>_<user name>.cred.

For signing we use:

  bin/hbgs_group_sign_<nnn>_<h> <base dir> <issuer name>_<nnn>_<h>_<user name> <T/F>

this signs a random hash and verifies the signature. It ouptuts the signature
size and the times to sign and verify the signature.

For example, using Hbgs_tests as the data directory:

   bin/generate_public_key_129 Hbgs_tests issuer

creates a file Hbgs_tests/issuer_129.pk.

   bin/generate_credential_129_1 Hbgs_tests issuer user0 F

creates a file Hbgs_tests/issuer_129_1_user0.cred.

   bin/hbgs_group_sign_129_1 Hbgs_tests issuer_129_1_user0 F

uses the credential to sign a random hash and then verifies the signature.

## License
The main body of code is licensed under the BSD two clause licence (see LICENSE.TXT).

The Picnic code that is used in this implementation has its own licence (see HBGS_picnic/LICENCE).
