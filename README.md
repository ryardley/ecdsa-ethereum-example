# ECDSA in Ethereum

An example of how ECDSA works in Ethereum in TypeScript

```ts
const sk = toHexString(crypto.randomBytes(32));
const kp = await keypair(sk);

const msg = "Hello World!";
const msgh = hash(msg);

const { r, s, v } = ecsign(msgh, kp.privateKey);
const pk = ecrecover(msgh, v, r, s);

assert(toHexString(kp.publicKey) == toHexString(pk)); // true
```