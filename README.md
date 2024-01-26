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

## Installation and Testing
For installation and testing see README.TXT.


