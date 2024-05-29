import { afterEach, beforeEach, describe } from "mocha";
import { Quantum } from "../src/quantum";
import nock from "nock";
import { assert } from "chai";

describe("check server connection", () => {
    let quantum: Quantum;
    let rpcEndPoint = "http://localhost:8000"
    beforeEach(() => {
        rpcEndPoint = "http://localhost:8000";
        quantum = new Quantum(rpcEndPoint, "auth");
    })
    it("should return false when status code is not 200 from server", async () => {
        const scope = nock(rpcEndPoint).get("/ping").reply(500);
        const response = await quantum.checkServerConnection();
        assert.equal(response, false, "should fail when incorrect status code is returned");
    })

    it("should return false when wrong data is returned from server", async () => {
        const scope = nock(rpcEndPoint).get("/ping").reply(200, "wrong_value");
        const response = await quantum.checkServerConnection();
        assert.equal(response, false, "should fail when wrong data code is returned");
    })

    it("should return true when correct data returned from server", async () => {
        const scope = nock(rpcEndPoint).get("/ping").reply(200, "pong");
        const response = await quantum.checkServerConnection();
        assert.equal(response, true, "should fail when incorrect status code is returned");
    })

    it("should return false when server replies with error", async () => {
        const scope = nock(rpcEndPoint).get("/ping").replyWithError("server down")
        const response = await quantum.checkServerConnection();
        assert.equal(response, false, "should fail when incorrect status code is returned");
    })
})