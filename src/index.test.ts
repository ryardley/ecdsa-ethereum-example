import crypto from "crypto";

import { ecrecover, ecsign, hash, keypair, toHexString } from "./index.js";

test("Can sign and verify a message", async () => {
  const sk = toHexString(crypto.randomBytes(32));
  const kp = await keypair(sk);

  console.log("Keypair", {
    pk: toHexString(kp.publicKey),
    sk: toHexString(kp.privateKey),
  });

  const msg = "Hello World!";
  const msgh = hash(msg);

  console.log("Message", {
    msg,
    hash: toHexString(msgh),
  });

  const { r, s, v } = ecsign(msgh, kp.privateKey);

  console.log("Signature", {
    r: toHexString(r),
    s: toHexString(s),
    v: v.toString(),
  });

  const pk = ecrecover(msgh, v, r, s);

  console.log("RecoveredPublicKey", {
    pk: toHexString(pk),
  });

  expect(toHexString(kp.publicKey)).toBe(toHexString(pk));
});
