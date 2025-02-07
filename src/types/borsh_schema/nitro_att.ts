const nitroAttVkeySchema = {
  struct: {
    pcr0_bytes: { array: { type: 'u8' } },
  }
}

const nitroAttProofSchema = {
  struct: {
    att_doc_bytes: { array: { type: 'u8' } }
  }
}

const nitroAttPisSchema = { array: { type: 'string' } };

export function getNitroAttVKeySchema() {
  return nitroAttVkeySchema;
}

export function getNitroAttProofSchema() {
  return nitroAttProofSchema;
}

export function getNitroAttPubInputSchema() {
  return nitroAttPisSchema;
}