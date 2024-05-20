import * as borsh from 'borsh';
import { getGnarkVKeySchema } from '../types/borsh_schema/gnark';
import fs from "fs";

export function borshSerialize(schema: any, value: any) {
    try {
        return borsh.serialize(schema, value);
    } catch (e) {
        throw new Error(`Error in serializing vkey: ${e}`)
    }
}

export function borshDeserialize(schema: any, encodedValue: any) {
    try {
        return borsh.deserialize(schema, encodedValue);
    } catch (e) {
        throw new Error(`Error in serializing vkey: ${e}`)
    }
}