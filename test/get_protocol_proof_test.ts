import { describe } from "mocha";
import { expect, assert } from 'chai';
import nock from "nock";
import { ProofType } from "../src/enum/proof_type";
import chaiAsPromised from "chai-as-promised";
import chai from "chai";
import { Quantum } from "../src/quantum";
import { ProofData } from "../src/types/proof_status";
import { ProtocolProof } from "../src/types/protocol_proof";

chai.use(chaiAsPromised);

describe("get protocol proof testing", () =>{
    let quantum: Quantum;
    let rpcEndPoint: string;
    let correctProofHash = "0xa4896a3f93bf4bf58378e579f3cf193bb4af1022af7d2089f37d8bae7157b85f";
    let correctProtocolProof = new ProtocolProof({
        protocolVkeyHash: "0x80dd52f677011d7b745fbb13675357cdb4418ca663c039124a22361b85f3b1a4",
        reductionVkeyHash: "0xa4896a3f93bf4bf58378e579f3cf193bb4af1022af7d2089f37d8bae7157b85f",
        merkleProofPosition: [13],
        merkleProof: [1,23,63,131],
        leafNextValue: "nextVal",
        leafNextIdx: [14],
    })
    beforeEach(() => {
        rpcEndPoint = "http://localhost:8000";
        quantum = new Quantum(rpcEndPoint, "auth");
    });

    it("should reject with an error when the request fails", async () => {
        nock(rpcEndPoint)
           .get(`/protocol_proof/merkle/${correctProofHash}`)
           .reply(500, { error: "Internal Server Error" });

        await expect(quantum.getProtocolProof (correctProofHash))
           .to.be.rejectedWith(/error in proof status api/);
    });

    it("should handle other unexpected errors", async () => {
        nock.cleanAll();

        await expect(quantum.getProtocolProof(correctProofHash))
           .to.be.rejectedWith(Error);
    });

    it("should return protocol proof response for correct proof hash", async() =>{
        let apiEndpoint = `/protocol_proof/merkle/${correctProofHash}`;
        const scope = nock(rpcEndPoint).get(apiEndpoint)
                                       .reply(200,
                                            {
                                                protocolVkeyHash: "0x80dd52f677011d7b745fbb13675357cdb4418ca663c039124a22361b85f3b1a4",
                                                reductionVkeyHash: "0xa4896a3f93bf4bf58378e579f3cf193bb4af1022af7d2089f37d8bae7157b85f",
                                                merkleProofPosition: [13],
                                                merkleProof: [1,23,63,131],
                                                leafNextValue: "nextVal",
                                                leafNextIdx: [14],
                                            }
                                        );
        let protocolProofRes = await quantum.getProtocolProof(correctProofHash);
        console.log(protocolProofRes);
        assert.deepEqual(protocolProofRes.protocolProof, correctProtocolProof);
    });
});