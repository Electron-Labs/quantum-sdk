import { beforeEach, describe } from "mocha";
import { Quantum } from "../src/quantum";
import nock from "nock";
import { assert, expect } from "chai";
import { ProofType } from "../src/enum/proof_type";
import chaiAsPromised from "chai-as-promised";
import chai from "chai";
chai.use(chaiAsPromised)

describe("register circuit", () => {
    let quantum: Quantum;
    let rpcEndPoint = "http://localhost:8000"
    const correctCircuitId = "0x80dd52f677011d7b745fbb13675357cdb4418ca663c039124a22361b85f3b1a4";
    beforeEach(() => {
        rpcEndPoint = "http://localhost:8000";
        quantum = new Quantum(rpcEndPoint);
    })

    it("should fail when vkey path is not valid", async () => {
        const scope = nock(rpcEndPoint).post("/register_circuit");
        return expect(quantum.registerCircuit("/doesnot/exist", 2, ProofType.GNARK_GROTH16)).to.be.rejectedWith(/^VkeyPath does not exist*/);
    })

    it("should fail in serialization when vkey json doesn't correspond to vkey schema", async () => {
        const scope = nock(rpcEndPoint).post("/register_circuit");
        return expect(quantum.registerCircuit("test/dump/wrong_vkey.json", 2, ProofType.GNARK_GROTH16)).to.be.rejectedWith(/^Error in serializing vkey*/);
    })

    it("should fail when node server replies with error", async () => {
        const scope = nock(rpcEndPoint).post("/register_circuit").replyWithError("server down");
        return expect(quantum.registerCircuit("test/dump/vkey.json", 2, ProofType.GNARK_GROTH16)).to.be.rejectedWith(/^error in register circuit api*/);
    })

    it("should return valid circuitId when correct path to correct vkey is provided", async () => {
        const scope = nock(rpcEndPoint).post("/register_circuit").reply(200, {circuit_hash: "0x80dd52f677011d7b745fbb13675357cdb4418ca663c039124a22361b85f3b1a4"});
        const circuitIdHash = await quantum.registerCircuit("test/dump/vkey.json", 2, ProofType.GNARK_GROTH16);
        assert.equal(circuitIdHash.asString(), correctCircuitId);
    })

})