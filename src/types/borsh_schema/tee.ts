const teeVkeySchema = {
  struct: {
    pcr0_bytes: { array: { type: 'u8' } },
  }
}

const teeProofSchema = {
  struct: {
    att_doc_bytes: { array: { type: 'u8' } }
  }
}

const teePisSchema = { array: { type: 'string' } };

export function getTeeVKeySchema() {
  return teeVkeySchema;
}

export function getTeeProofSchema() {
  return teeProofSchema;
}

export function getTeePubInputSchema() {
  return teePisSchema;
}