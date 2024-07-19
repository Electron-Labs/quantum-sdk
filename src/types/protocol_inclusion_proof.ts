export interface ProtocolInclusionProof {
  merkleProofPosition: number;
  merkleProof: string[];
  leafNextValue: string;
  leafNextIdx: string;
  pubInputs: Uint8Array[];
};
