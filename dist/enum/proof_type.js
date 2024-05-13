"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProofType = void 0;
var ProofType;
(function (ProofType) {
    ProofType[ProofType["GROTH16"] = 1] = "GROTH16";
    ProofType[ProofType["GNARK_GROTH16"] = 2] = "GNARK_GROTH16";
    ProofType[ProofType["PLONKY2"] = 3] = "PLONKY2";
    ProofType[ProofType["HALO2_KZG"] = 4] = "HALO2_KZG";
})(ProofType || (exports.ProofType = ProofType = {}));
