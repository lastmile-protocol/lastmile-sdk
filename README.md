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
| `@lastmile/sdk/anchor` | yes | on- and off-ramp through a licensed anchor |

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

## Getting cash in and out

Two ramps, because they solve different problems.

The **cash desk** is a person with a cash box: an agent takes naira and signs a
voucher, or redeems a voucher and hands over naira. It needs no licence, no
bank and no connectivity on the customer's side, which is the whole reason it
exists. That lives in the wallet, not here.

The other ramp is banks, mobile money and cards, and that needs a licence
Lastmile does not have and should not pretend to. Stellar's answer is anchors:
regulated businesses that take fiat in and issue tokens out. `@lastmile/sdk/anchor`
is a client for them — SEP-1 to find one, SEP-10 to authenticate, SEP-24 to hand
the customer off to the anchor's own hosted flow for the bank details and the
identity checks. It integrates an anchor. It is not one.

```js
import { connectAnchor } from '@lastmile/sdk/anchor';

const anchor = await connectAnchor({ homeDomain: 'testanchor.stellar.org' });
await anchor.info();                 // what it takes in, pays out, and the limits

const token = await anchor.authenticate(account, signHash);
const { url, id } = await anchor.start('deposit', {
  assetCode: 'USDC', token, account, amount: 25,
});
// open `url`; poll `anchor.transaction(id, token)` for where it got to
```

### Why `signHash` and not a secret key

SEP-10 authentication means signing a challenge transaction with the user's own
key. In this wallet that key is a non-extractable `CryptoKey` in the browser: it
signs on request and refuses to be exported, which is the property worth having.
So the signing is split. This module does the protocol and the XDR and hands out
the 32 bytes to sign; `signHash` returns 64 bytes of ed25519 signature. The key
never passes through here, and does not have to exist in a form that could.

`challenge()` also returns that hash **and the anchor's own signature over it**,
as hex. A wallet holding the key can check that the anchor vouched for exactly
the bytes it is about to sign, without parsing a byte of XDR.

### What the client refuses to sign

A challenge is a transaction, and a transaction signed carelessly moves money.
What makes a SEP-10 challenge safe is a set of properties, and they are checked
rather than assumed:

- **sequence number 0** — so the thing can never be submitted, whatever it says
- **source is the anchor's published `SIGNING_KEY`**, from its own `stellar.toml`
- **every operation is a `manage_data`** — no payment rides along
- **the first operation is sourced by your account** — not somebody else's
- **its key is `"<home domain> auth"`** — a token minted for another domain is not
  a token for this one
- **the anchor has already signed it** — so the bytes came from the party you chose

Each of those has a test that builds the violating challenge for real and watches
it be refused. A validator tested only on good input is indistinguishable from
one that returns `true`.

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

49 of them. The offline suite squeezes a voucher through transport and checks it
means the same thing coming out, and that an edited one does not. The chain suite
covers what must work before any network call: recovering a contract error from
every envelope it arrives in, and refusing a truncated key before it becomes a
transaction someone paid for. The anchor suite builds each malformed challenge
with the same library an anchor would use, and checks it is refused — plus the
SDF test anchor's real `stellar.toml`, recorded verbatim, so the parser has met a
document somebody actually serves.

## Licence

Apache-2.0.
