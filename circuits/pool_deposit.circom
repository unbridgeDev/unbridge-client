pragma circom 2.0.0;

// Deposit-only circuit. A deposit has NO spent inputs (money enters the pool), so it
// needs none of the transact circuit's expensive input machinery: no EdDSA threshold
// signature verification, no Merkle membership proofs, no nullifiers. All it must enforce
// is that the two new output notes are well-formed and their amounts sum to the public
// deposited amount — otherwise a depositor could mint notes worth more than they paid in.
// This is ~10x smaller than PoolTx, so a deposit proves in a fraction of the time.
include "poseidon.circom";
include "bitify.circom";

template PoolDeposit(nOuts) {
    signal input publicAmount;      // the deposited amount (public boundary denomination)
    signal input extDataHash;       // binds recipient/enc/fee params (replay protection)
    signal input mintAddress;

    signal input outputCommitment[nOuts];
    signal input outAmount[nOuts];
    signal input outPubkey[nOuts];
    signal input outBlinding[nOuts];

    component outCommitmentHasher[nOuts];
    component outAmountCheck[nOuts];
    var sumOuts = 0;
    for (var tx = 0; tx < nOuts; tx++) {
        // commitment = Poseidon(amount, owner, blinding, mint) — identical shape to PoolTx
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

    // no inputs, so sumIns = 0: the deposited public amount must equal the notes created
    publicAmount === sumOuts;
    // bind extDataHash into the constraint system (same as PoolTx)
    signal extDataSquare <== extDataHash * extDataHash;
}

component main {public [publicAmount, extDataHash, outputCommitment]} = PoolDeposit(2);
