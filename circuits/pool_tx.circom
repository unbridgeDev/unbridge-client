pragma circom 2.0.0;

// Phase 2: the real shielded-pool transaction circuit, but with Privacy Cash's
// key-preimage spend authority replaced by a THRESHOLD SIGNATURE (FROST). This is
// the Tornado-Nova join/split with two swaps:
//   (1) spend auth: an EdDSA-Poseidon signature (R8,S) under the note's owner key
//       A=(Ax,Ay) over a spend message — produced by FROST, key never reconstructed
//       (vs `publicKey = Poseidon(privateKey)` knowledge).
//   (2) nullifier: derived from a separate nullifier key `nk` bound into the note,
//       NOT from the (randomised) signature — so it stays deterministic (one note ->
//       one nullifier, double-spend safe). nk gives no spend power; only the group
//       signature can spend. (Sapling ak/nk split.)
//
// Note: {amount, owner=Poseidon(Ax,Ay,nk), blinding, mint}. commitment keeps the
// original arity-4 shape. Spike is nIns=1/nOuts=1; the real pool loops to 2/2.
include "poseidon.circom";
include "bitify.circom";
include "switcher.circom";
include "comparators.circom";
include "eddsaposeidon.circom";

template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices;
    signal output root;

    component switcher[levels];
    component hasher[levels];
    component indexBits = Num2Bits(levels);
    indexBits.in <== pathIndices;

    for (var i = 0; i < levels; i++) {
        switcher[i] = Switcher();
        switcher[i].L <== i == 0 ? leaf : hasher[i - 1].out;
        switcher[i].R <== pathElements[i];
        switcher[i].sel <== indexBits.out[i];
        hasher[i] = Poseidon(2);
        hasher[i].inputs[0] <== switcher[i].outL;
        hasher[i].inputs[1] <== switcher[i].outR;
    }
    root <== hasher[levels - 1].out;
}

template PoolTx(levels, nIns, nOuts) {
    signal input root;
    signal input publicAmount;
    signal input extDataHash;
    signal input mintAddress;

    // inputs (spent notes)
    signal input inputNullifier[nIns];
    signal input inAmount[nIns];
    signal input inAx[nIns];        // owner group public key (Baby Jubjub point)
    signal input inAy[nIns];
    signal input inNk[nIns];        // nullifier key (bound in note; no spend power)
    signal input inBlinding[nIns];
    signal input inPathIndices[nIns];
    signal input inPathElements[nIns][levels];
    signal input inR8x[nIns];       // threshold signature over the spend message
    signal input inR8y[nIns];
    signal input inS[nIns];
    // association-set membership: each spent commitment must be in the vetted set.
    // (Deposits-only pool ⇒ a spent note is always a direct deposit output, so its own
    // commitment is the association leaf — no separate label needed until internal
    // transfers exist.)
    signal input inAssocPathIndices[nIns];
    signal input inAssocPathElements[nIns][levels];

    // outputs (new notes)
    signal input outputCommitment[nOuts];
    signal input outAmount[nOuts];
    signal input outPubkey[nOuts];  // output owner field (= Poseidon(Ax,Ay,nk) of the recipient note)
    signal input outBlinding[nOuts];

    // Declared LAST among public inputs so it becomes public input 7 (circom orders
    // public signals by declaration order, not by the main.public list). Keeps the
    // program's existing public-input indices 0..6 unchanged.
    signal input associationRoot;   // Privacy Pools: root of the vetted-commitment set

    component inOwner[nIns];
    component inCommitmentHasher[nIns];
    component inMsgHasher[nIns];
    component inAmtZero[nIns];
    component inSig[nIns];
    component inNullifierHasher[nIns];
    component inTree[nIns];
    component inCheckRoot[nIns];
    component inAssocTree[nIns];
    component inAssocCheck[nIns];
    var sumIns = 0;

    for (var tx = 0; tx < nIns; tx++) {
        // owner = Poseidon(Ax, Ay, nk)
        inOwner[tx] = Poseidon(3);
        inOwner[tx].inputs[0] <== inAx[tx];
        inOwner[tx].inputs[1] <== inAy[tx];
        inOwner[tx].inputs[2] <== inNk[tx];

        // commitment = Poseidon(amount, owner, blinding, mint)
        inCommitmentHasher[tx] = Poseidon(4);
        inCommitmentHasher[tx].inputs[0] <== inAmount[tx];
        inCommitmentHasher[tx].inputs[1] <== inOwner[tx].out;
        inCommitmentHasher[tx].inputs[2] <== inBlinding[tx];
        inCommitmentHasher[tx].inputs[3] <== mintAddress;

        // spend message M = Poseidon(commitment, pathIndices, extDataHash) — binds the
        // group's signature to THIS note, position, and withdrawal params (no replay)
        inMsgHasher[tx] = Poseidon(3);
        inMsgHasher[tx].inputs[0] <== inCommitmentHasher[tx].out;
        inMsgHasher[tx].inputs[1] <== inPathIndices[tx];
        inMsgHasher[tx].inputs[2] <== extDataHash;

        // verify threshold EdDSA signature under the note's owner key
        // (only for real inputs; zero-amount padding inputs skip the check)
        inAmtZero[tx] = IsZero();
        inAmtZero[tx].in <== inAmount[tx];
        inSig[tx] = EdDSAPoseidonVerifier();
        inSig[tx].enabled <== 1 - inAmtZero[tx].out;
        inSig[tx].Ax <== inAx[tx];
        inSig[tx].Ay <== inAy[tx];
        inSig[tx].S <== inS[tx];
        inSig[tx].R8x <== inR8x[tx];
        inSig[tx].R8y <== inR8y[tx];
        inSig[tx].M <== inMsgHasher[tx].out;

        // nullifier = Poseidon(commitment, pathIndices, nk) — deterministic
        inNullifierHasher[tx] = Poseidon(3);
        inNullifierHasher[tx].inputs[0] <== inCommitmentHasher[tx].out;
        inNullifierHasher[tx].inputs[1] <== inPathIndices[tx];
        inNullifierHasher[tx].inputs[2] <== inNk[tx];
        inNullifierHasher[tx].out === inputNullifier[tx];

        // membership in the tree
        inTree[tx] = MerkleProof(levels);
        inTree[tx].leaf <== inCommitmentHasher[tx].out;
        inTree[tx].pathIndices <== inPathIndices[tx];
        for (var i = 0; i < levels; i++) inTree[tx].pathElements[i] <== inPathElements[tx][i];

        inCheckRoot[tx] = ForceEqualIfEnabled();
        inCheckRoot[tx].in[0] <== root;
        inCheckRoot[tx].in[1] <== inTree[tx].root;
        inCheckRoot[tx].enabled <== inAmount[tx];

        // association-set membership of the SAME commitment (skipped for zero-amount
        // padding inputs). Proves the spent funds trace to a vetted deposit without
        // revealing which — the withdrawal-side "prove clean" gate.
        inAssocTree[tx] = MerkleProof(levels);
        inAssocTree[tx].leaf <== inCommitmentHasher[tx].out;
        inAssocTree[tx].pathIndices <== inAssocPathIndices[tx];
        for (var i = 0; i < levels; i++) inAssocTree[tx].pathElements[i] <== inAssocPathElements[tx][i];

        inAssocCheck[tx] = ForceEqualIfEnabled();
        inAssocCheck[tx].in[0] <== associationRoot;
        inAssocCheck[tx].in[1] <== inAssocTree[tx].root;
        inAssocCheck[tx].enabled <== inAmount[tx];

        sumIns += inAmount[tx];
    }

    component outCommitmentHasher[nOuts];
    component outAmountCheck[nOuts];
    var sumOuts = 0;
    for (var tx = 0; tx < nOuts; tx++) {
        outCommitmentHasher[tx] = Poseidon(4);
        outCommitmentHasher[tx].inputs[0] <== outAmount[tx];
        outCommitmentHasher[tx].inputs[1] <== outPubkey[tx];
        outCommitmentHasher[tx].inputs[2] <== outBlinding[tx];
        outCommitmentHasher[tx].inputs[3] <== mintAddress;
        outCommitmentHasher[tx].out === outputCommitment[tx];

        outAmountCheck[tx] = Num2Bits(248);
        outAmountCheck[tx].in <== outAmount[tx];
        sumOuts += outAmount[tx];
    }

    // no duplicate nullifiers among inputs
    component sameNullifiers[nIns * (nIns - 1) / 2];
    var idx = 0;
    for (var i = 0; i < nIns - 1; i++) {
        for (var j = i + 1; j < nIns; j++) {
            sameNullifiers[idx] = IsEqual();
            sameNullifiers[idx].in[0] <== inputNullifier[i];
            sameNullifiers[idx].in[1] <== inputNullifier[j];
            sameNullifiers[idx].out === 0;
            idx++;
        }
    }

    // amount invariant
    sumIns + publicAmount === sumOuts;
    signal extDataSquare <== extDataHash * extDataHash;
}

// associationRoot appended LAST so the program's existing public-input indices (0..6)
// are unchanged; it becomes public input 7 (8 total).
component main {public [root, publicAmount, extDataHash, inputNullifier, outputCommitment, associationRoot]} = PoolTx(26, 2, 2);
