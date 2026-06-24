pragma circom 2.0.0;

// Spike 1a: prove — in a Groth16 circuit, single-party — that a note's spend was
// authorized by a Baby Jubjub EdDSA-Poseidon SIGNATURE from the note's owner key,
// instead of Privacy Cash's `publicKey = Poseidon(privateKey)` preimage check.
//
// This is the swap that lets FROST drive spending: the note is owned by a public
// key A=(Ax,Ay); to spend you present a signature (R8,S) over the spend message M.
// The signing key is never in the witness -> it can be threshold-shared (FROST),
// and the heavy proof is produced by ONE party (fast), not co-computed.
include "eddsaposeidon.circom";

template SpendAuth() {
    signal input Ax;   // public: owner (group) public key
    signal input Ay;
    signal input M;    // public: the spend authorization message
    signal input S;    // private: signature scalar
    signal input R8x;  // private: signature nonce point
    signal input R8y;

    component v = EdDSAPoseidonVerifier();
    v.enabled <== 1;
    v.Ax <== Ax;
    v.Ay <== Ay;
    v.S <== S;
    v.R8x <== R8x;
    v.R8y <== R8y;
    v.M <== M;
}

component main {public [Ax, Ay, M]} = SpendAuth();
