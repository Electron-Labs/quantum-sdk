import { describe } from "mocha";
import { expect } from "chai";
import { ProofStatus } from "../src/enum/proof_status";
import { ProofData } from "../src/types/proof_status";

describe("proof status", () => {
    it("testing construction", () => {
        const transactionHash = "0x4dc70783f07ab7c5397a2f8ce213e1ced2b6332322763563eac3ded0b537f3d7";
        const superproofId = 245;
        const verificationContract = "0xDF11C90D1882257690Dca8f6b5013CFd75aBf347"

        let fields = {
            status : ProofStatus.VERIFIED,
            superproofId,
            transactionHash,
            verificationContract
        }
        const proofStatus = new ProofData({...fields});
        expect(proofStatus.status, "proof state is not as expected").to.equal(ProofStatus.VERIFIED);
        expect(proofStatus.superproofId, "superproof Id is not correctly set").to.equal(superproofId);
        expect(proofStatus.transactionHash, "transaction hash is not correct").to.equal(transactionHash);
        expect(proofStatus.verificationContract, "verification contract is not correct").to.equal(verificationContract);
    })
})