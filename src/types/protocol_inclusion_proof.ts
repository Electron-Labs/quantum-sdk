export interface ProtocolInclusionProof {
  protocolVKeyHash: string;
  reductionVKeyHash: string;
  merkleProofPosition: number;
  merkleProof: string[];
  leafNextValue: string;
  leafNextIdx: string;
  pubInputs: Uint8Array[] | undefined;
};
