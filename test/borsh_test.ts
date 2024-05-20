import { describe } from "mocha"
import { readJsonFile } from "../src/utils/file";
import { assert } from "chai";
import { borshDeserialize, borshSerialize } from "../src/utils/borsh";
import { getSnarkJSVkeySchema } from "../src/types/borsh_schema/SnarkJS";
import { getGnarkVKeySchema } from "../src/types/borsh_schema/gnark";

describe("borsh serialize and deserialize test", () => {
    it("checking serialize and deserialize of snark", () => {
        let circomVkeySchema = getSnarkJSVkeySchema();
        let vkeyJson = readJsonFile("test/dump/circom1_vk.json")
        let serializedVley = borshSerialize(circomVkeySchema, vkeyJson);
        let deserializedKey = borshDeserialize(circomVkeySchema, serializedVley);
        assert.deepEqual(vkeyJson, deserializedKey);
    })

    it("checking serialize and deserialize of gnark", () => {
        let circomVkeySchema = getGnarkVKeySchema();
        let vkeyJson = readJsonFile("test/dump/vkey.json")
        let serializedVley = borshSerialize(circomVkeySchema, vkeyJson);
        let deserializedKey = borshDeserialize(circomVkeySchema, serializedVley);
        assert.deepEqual(vkeyJson, deserializedKey);
    })
})