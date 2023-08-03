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

## References

- https://github.com/MetaMask/eth-simple-keyring/blob/main/src/simple-keyring.ts
- https://github.com/ethereum/js-ethereum-cryptography#readme
- https://github.com/paulmillr/noble-curves