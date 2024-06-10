import { describe } from "mocha";
import { expect, assert } from 'chai';
import nock from "nock";
import { ProofType } from "../src/enum/proof_type";
import chaiAsPromised from "chai-as-promised";
import chai from "chai";
import { Quantum } from "../src/quantum";

chai.use(chaiAsPromised);

describe("submit proof test", () => {
    let quantum: Quantum;
    let rpcEndPoint: string;
    let correctPisPath = "test/dump/snark/proof/3/015c3f5b-3ad6-4025-92ff-54832b48dd57/public.json";
    let correctProofPath = "test/dump/snark/proof/3/015c3f5b-3ad6-4025-92ff-54832b48dd57/proof.json"
    let circuitHash = "0x80dd52f677011d7b745fbb13675357cdb4418ca663c039124a22361b85f3b1a4";
    let correctProofHash = "0xa4896a3f93bf4bf58378e579f3cf193bb4af1022af7d2089f37d8bae7157b85f"; 

    beforeEach(() => {
        rpcEndPoint = "http://localhost:8000";
        quantum = new Quantum(rpcEndPoint, "auth");
    }); 

    it("should fail when JSON or Pis file is not valid", () => {
        const scope = nock(rpcEndPoint).post("/proof");
        let invalidPath = "/src/invalid_path.json";
        return expect(quantum.submitProof(invalidPath, correctPisPath, circuitHash, ProofType.GROTH16))
        .to.be.rejectedWith(/^filePath does not exist*/);
    });
    
    it("should fail to serialize when proof file is doesnot matches proof type schema", () => {
        const scope = nock(rpcEndPoint).post("/proof");
        let invalidProofJSON = "test/dump/wrong_proof.json";
        return expect(quantum.submitProof(invalidProofJSON, correctPisPath, circuitHash, ProofType.GROTH16))
        .to.be.rejectedWith(/^Error in serializing*/);
    });

    it("should fail to serialize pub inputs when schema does not match", () => {
        const scope = nock(rpcEndPoint).post("/proof");
        let invalidPisPath = "test/dump/wrong_public.json";
        return expect(quantum.submitProof(correctProofPath, invalidPisPath, circuitHash, ProofType.GROTH16))
        .to.be.rejectedWith(/^Error in serializing*/);;
    });

    it("should return valid proof_hash when valid proof and pub inputs are provided", async() => {
        const scope = nock(rpcEndPoint).post("/proof").reply(200, {proof_id: "0xa4896a3f93bf4bf58378e579f3cf193bb4af1022af7d2089f37d8bae7157b85f"});
        let submittedProofRes = await quantum.submitProof(correctProofPath, correctPisPath, circuitHash, ProofType.GROTH16);
        console.log(submittedProofRes);
        let proofHash = submittedProofRes.proofHash.asString();
        assert.equal(proofHash, correctProofHash);
    });
});