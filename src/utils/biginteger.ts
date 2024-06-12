import BigInteger from 'big-integer';

const zero = BigInteger(0);
const n256 = BigInteger(256);

export function toLeBytes32(value: string): Uint8Array {
  let bigNumber = BigInteger(value)
  let result = new Uint8Array(32)
  let i = 0;
  while (bigNumber.greater(zero)) {
    result[i] = bigNumber.mod(n256).valueOf()
    bigNumber = bigNumber.divide(n256);
    i += 1;
  }
  return result;
}