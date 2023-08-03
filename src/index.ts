import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

export interface ECDSASignature {
  v: bigint; // recovery
  r: Uint8Array;
  s: Uint8Array;
}

export function isHexPrefixed(str: string): boolean {
  if (typeof str !== "string") {
    throw new Error(
      `[isHexPrefixed] input must be type 'string', received type ${typeof str}`
    );
  }

  return str[0] === "0" && str[1] === "x";
}

export const stripHexPrefix = (str: string): string => {
  if (typeof str !== "string")
    throw new Error(
      `[stripHexPrefix] input must be type 'string', received ${typeof str}`
    );

  return isHexPrefixed(str) ? str.slice(2) : str;
};

export const concatBytes = (...arrays: Uint8Array[]): Uint8Array => {
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
};

export const zeros = (bytes: number): Uint8Array => {
  return new Uint8Array(bytes);
};

const setLength = (
  msg: Uint8Array,
  length: number,
  right: boolean
): Uint8Array => {
  if (right) {
    if (msg.length < length) {
      return new Uint8Array([...msg, ...zeros(length - msg.length)]);
    }
    return msg.subarray(0, length);
  } else {
    if (msg.length < length) {
      return new Uint8Array([...zeros(length - msg.length), ...msg]);
    }
    return msg.subarray(-length);
  }
};

export const privateToPublic = function (privateKey: Uint8Array): Uint8Array {
  return secp256k1.ProjectivePoint.fromPrivateKey(privateKey)
    .toRawBytes(false)
    .slice(1);
};

export async function keypair(sk: string) {
  const strippedHexPrivateKey = stripHexPrefix(sk);
  const privateKey = new Uint8Array(Buffer.from(strippedHexPrivateKey, "hex"));
  const publicKey = privateToPublic(privateKey);
  return { privateKey, publicKey };
}

export function hash(msg: string) {
  return keccak_256(Buffer.from(msg));
}

export function ecsign(
  msgHash: Uint8Array,
  privateKey: Uint8Array
): ECDSASignature {
  const sig = secp256k1.sign(msgHash, privateKey);
  const buf = sig.toCompactRawBytes();
  const r = buf.slice(0, 32);
  const s = buf.slice(32, 64);

  // In Ethereum, `v` is used for public key recovery.
  // Given the signature `(r, s, v)` of a certain hash of a message,
  // one can recover the public key of the signer.
  const v = BigInt(sig.recovery! + 27);
  return { r, s, v };
}

export const setLengthLeft = (msg: Uint8Array, length: number): Uint8Array => {
  return setLength(msg, length, false);
};

function calculateSigRecovery(v: bigint, chainId?: bigint): bigint {
  if (v === BigInt(0) || v === BigInt(1)) return v;

  if (chainId === undefined) {
    return v - BigInt(27);
  }
  return v - (chainId * BigInt(2) + BigInt(35));
}

function isValidSigRecovery(recovery: bigint): boolean {
  return recovery === BigInt(0) || recovery === BigInt(1);
}

// Use ecrecover to verify a signature
export function ecrecover(
  msgHash: Uint8Array,
  v: bigint,
  r: Uint8Array,
  s: Uint8Array,
  chainId?: bigint
): Uint8Array {
  const signature = concatBytes(setLengthLeft(r, 32), setLengthLeft(s, 32));
  const recovery = calculateSigRecovery(v, chainId);
  if (!isValidSigRecovery(recovery)) {
    throw new Error("Invalid signature v value");
  }

  const sig = secp256k1.Signature.fromCompact(signature).addRecoveryBit(
    Number(recovery)
  );
  const senderPubKey = sig.recoverPublicKey(msgHash);
  return senderPubKey.toRawBytes(false).slice(1);
}

export function toHexString(input: Uint8Array): string {
  return Buffer.from(input).toString("hex");
}
