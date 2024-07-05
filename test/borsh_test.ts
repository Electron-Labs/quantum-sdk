import { describe } from "mocha"
import { readJsonFile } from "../src/utils/file";
import { assert } from "chai";
import { borshDeserialize, borshSerialize } from "../src/utils/borsh";
import { getSnarkJSVkeySchema } from "../src/types/borsh_schema/SnarkJS";
import { getGnarkVKeySchema } from "../src/types/borsh_schema/gnark";
import { deserializeProof, deserializeVkey, serializeProof, serializeVKey } from "../src/quantum_helper";
import { ProofType } from "../src/enum/proof_type";

describe("borsh serialize and deserialize test", () => {
    it("checking serialize and deserialize of snark vk", () => {
        let vkeyJson = readJsonFile("test/dump/snark/circuit/2/vkey.json")
        let serializedVley = serializeVKey(vkeyJson, ProofType.GROTH16);
        let deserializedKey = deserializeVkey(serializedVley, ProofType.GROTH16);
        assert.deepEqual(vkeyJson, deserializedKey);
    })

    it("checking serialize and deserialize of gnark vk", () => {
        let vkeyJson = readJsonFile("test/dump/gnark/circuit/2/vkey.json")
        let serializedVley = serializeVKey(vkeyJson, ProofType.GNARK_GROTH16);
        let deserializedKey = deserializeVkey( serializedVley, ProofType.GNARK_GROTH16);
        assert.deepEqual(vkeyJson, deserializedKey);
    })

    it("checking serialize and deserialize of snark proof", () => {
        let pkeyJson = readJsonFile("test/dump/snark/proof/2/aa8a0176-cab8-443c-aff8-2c8d9585e716/proof.json")
        let serializedPKey = serializeProof(pkeyJson, ProofType.GROTH16);
        let deserializedKey = deserializeProof(serializedPKey, ProofType.GROTH16);
        assert.deepEqual(pkeyJson, deserializedKey);
    })

    it("checking serialize and deserialize of gnark proof", () => {
        let pkeyJson = readJsonFile("test/dump/gnark/proof/2/561f24b4-e89c-477d-a72d-01f749b30ff9/proof.json")
        let serializedPKey = serializeProof(pkeyJson, ProofType.GNARK_GROTH16);
        let deserializedKey = deserializeProof( serializedPKey, ProofType.GNARK_GROTH16);
        assert.deepEqual(pkeyJson, deserializedKey);
    })
})