"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProofState = void 0;
var ProofState;
(function (ProofState) {
    ProofState[ProofState["PROOF_NOT_FOUND"] = 0] = "PROOF_NOT_FOUND";
    ProofState[ProofState["PROOF_SUBMITTED"] = 1] = "PROOF_SUBMITTED";
    ProofState[ProofState["PROOF_AGGREGATED"] = 2] = "PROOF_AGGREGATED";
    ProofState[ProofState["SUPERPROOF_VERIFIED"] = 3] = "SUPERPROOF_VERIFIED";
})(ProofState || (exports.ProofState = ProofState = {}));
