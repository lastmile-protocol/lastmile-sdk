# lastmile-sdk

Sign a Stellar payment with no connectivity. Redeem it when signal returns.

Every Stellar payment product assumes both parties are online. Stellar's best
markets are the places where that is least true. Lastmile splits **authorisation**
from **settlement**: a phone with no signal signs a voucher, it travels by QR, NFC
or SMS, and whoever reaches a network first submits it.

```js
import { sign, pack, unpack, verify } from '@lastmile/sdk';

// On a phone with no signal. Nothing here touches the network.
const voucher = sign({
  payer:   'GDHY…',        // whose float this is drawn from
  payee:   'GBGY…',        // who may redeem it
  amount:  '25000000',     // stroops
  nonce:   '7',            // unique per payer; reusing one is provable fraud
  expires: '1789393424',   // unix seconds
}, deviceSecret);

const code = pack(voucher);  // 246 characters -> a QR code

// On the other side, still offline: the payee checks the signature before
// handing over the goods.
verify(unpack(code));        // true
```

## Two halves, imported separately

| import | needs a network | what it does |
| --- | --- | --- |
| `@lastmile/sdk` | no | payload, sign, verify, pack, unpack |
| `@lastmile/sdk/chain` | yes | redeem, and read vault state |

The split is the point. A wallet that only ever signs never loads an RPC client,
and the offline half runs unchanged in a browser — no `Buffer`, no `node:crypto`.
A wallet that has to work with the radio off cannot depend on a server runtime
being underneath it.

```js
import { connect } from '@lastmile/sdk/chain';

const vault = connect({ contractId: 'CB5Z…' });   // defaults to testnet

// Free, simulated, submits nothing: for a payee with a moment of signal and a
// long walk home.
await vault.wouldRedeem(voucher);                 // true / false
await vault.vaultOf(payer);                       // { token, float, bond }
await vault.isSpent(payer, nonce);                // has this nonce been used?

// Settles on chain. Permissionless — the signature is the authority, not the
// sender — but a Stellar transaction still needs someone to pay the fee.
const { hash, ledger } = await vault.redeem(voucher, submitterSecret);
```

A failed call throws a `LastmileError` carrying the contract's own error code, so
you can branch on `e.code === 6` ("already redeemed") rather than parse a string.

## Two things this library refuses to do quietly

**Round a number.** A u64 nonce reaches 18446744073709551615. A JavaScript number
is exact only to 9007199254740991. Past that, `JSON.parse` rounds *silently*, and
you sign a hash for an authorization nobody wrote — no error, nothing to see, just
a signature that verifies against nothing. Pass large values as strings or
BigInts; anything already corrupted is rejected rather than encoded.

**Guess the payload.** A Soroban `contracttype` struct is an ScVal map whose
symbol keys are **sorted**, and the sort order is load-bearing: get it wrong and
the hash differs with no complaint from anything. `payload()` is checked
byte-for-byte against the deployed contract's own `signing_payload`, across
i128 and u64 extremes.

## The wire format

184 bytes, base64url — 246 characters.

```
0    payer      32   raw ed25519
32   payee      32
64   amount      8   stroops, big-endian signed
72   nonce       8
80   expires     8
88   device     32   the key that signed
120  signature  64
```

Small enough for a QR code, one NFC tap, or two SMS. Not small enough to read
aloud: a spoken code needs a scheme that *looks the payee up* rather than
carrying them, which is not built and would be dishonest to claim.

The contract's `amount` is an i128; this format carries 64 bits of it — about
922 billion XLM, far past any offline float. An amount above that is rejected
here rather than silently truncated on its way to a signature.

## What it does not protect against

Offline double-spend cannot be prevented in software. That is not a gap in this
design; it is why every serious offline CBDC design uses secure hardware. The
contract bounds it (a payer risks only the float they locked) and makes one form
of it provable (two signatures on one nonce is a signed confession anyone can
submit, which slashes the payer's bond). A payer can still overspend across
*distinct* nonces; those redemptions fail first-come-first-served and the late
payee is not paid. That is the risk a merchant takes accepting a cheque.

## Tests

```
npm test
```

19 of them. The offline suite squeezes a voucher through transport and checks it
means the same thing coming out, and that an edited one does not. The chain suite
covers what must work before any network call: recovering a contract error from
every envelope it arrives in, and refusing a truncated key before it becomes a
transaction someone paid for.

## Licence

Apache-2.0.
