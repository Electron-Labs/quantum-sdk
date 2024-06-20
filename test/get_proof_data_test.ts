import { describe } from "mocha";
import { expect, assert } from 'chai';
import nock from "nock";
import { ProofType } from "../src/enum/proof_type";
import chaiAsPromised from "chai-as-promised";
import chai from "chai";
import { Quantum } from "../src/quantum";
import { ProofData } from "../src/types/proof_status";

chai.use(chaiAsPromised);

describe("get proof data test", () => {
    let quantum: Quantum;
    let rpcEndPoint: string;
    let correctProofHash = "0xa4896a3f93bf4bf58378e579f3cf193bb4af1022af7d2089f37d8bae7157b85f"; 
    let correctProofData = new ProofData({
        status: 2,
        superproofId: 100,
        transactionHash: null,
        verificationContract: {
            address: "0xf9b3ef0b33ebfb4160d70c1b7a1d213a6847baf7"
        }
    });
    beforeEach(() => {
        rpcEndPoint = "http://localhost:8000";
        quantum = new Quantum(rpcEndPoint, "auth");
    });

    it("should return GetProofDataResponse if valid test cases are provided", async() => {
        let apiEndpoint = `/proof/${correctProofHash}`;
        console.log("api Endpoint: ", apiEndpoint);
        const scope = nock(rpcEndPoint).get(apiEndpoint)
                                       .reply(200, 
                                            {
                                                    status: "Registered", 
                                                    superproof_id: 100, 
                                                    transaction_hash: null, 
                                                    verification_contract: "0xf9b3ef0b33ebfb4160d70c1b7a1d213a6847baf7"
                                             }
                                            );
        let proofDataRes = await quantum.getProofData(correctProofHash);
        assert.deepEqual(proofDataRes.proofData , correctProofData);
    });

    it('should handle server errors',  () => {
        nock(rpcEndPoint)
           .get(`/proof/${correctProofHash}`)
           .reply(500, { error: 'Internal Server Error' });
        
        return expect(quantum.getProofData(correctProofHash)).to.be
                .rejectedWith(/^error in proof status api*/);
    });
});