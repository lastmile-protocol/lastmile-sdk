// Anchors: the regulated end of the ramp.
//
// The cash desk handles the part of on- and off-ramping that needs no licence:
// a person with a cash box. This file handles the other part -- banks, mobile
// money, cards -- which needs one, and which Lastmile therefore does not do
// itself. Stellar's answer is anchors: licensed businesses that take fiat in and
// issue tokens out, and vice versa. The standards that talk to them are SEP-1
// (discovery), SEP-10 (authentication) and SEP-24 (the hosted deposit and
// withdrawal flow). All of this is client-side. It integrates an anchor; it does
// not pretend to be one.
//
// The interesting problem is SEP-10. Authenticating means signing a challenge
// transaction with the user's own key, and in this wallet that key lives in the
// browser and never leaves it. So the signing is split: this module does the
// protocol and the XDR, and hands out a 32-byte hash for something else to sign.
// See `authenticate` for why that is safe to do.

import { Keypair, Transaction, Networks } from '@stellar/stellar-sdk';
import { fromHex, toHex, toBase64 } from './bytes.js';

export class AnchorError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = 'AnchorError';
    this.detail = detail;
  }
}

const GOOD_ACCOUNT = /^G[A-Z2-7]{55}$/;

// ---------------------------------------------------------------- SEP-1

/**
 * Parse the handful of stellar.toml fields an anchor client needs.
 *
 * Deliberately not a general TOML parser. A wallet needs six keys and a list of
 * currencies, and a small reader whose failure modes are obvious beats a large
 * one whose are not.
 */
const ELSEWHERE = Symbol('another table');

export function parseToml(text) {
  const out = { currencies: [] };
  let current = null;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line) continue;
    if (line === '[[CURRENCIES]]') {
      current = {};
      out.currencies.push(current);
      continue;
    }
    if (/^\[\[?/.test(line)) {
      current = ELSEWHERE; // some other table; its keys are not ours
      continue;
    }
    const m = /^([A-Za-z0-9_]+)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = m[2].trim();
    if (/^".*"$/.test(value) || /^'.*'$/.test(value)) value = value.slice(1, -1);
    else if (value === 'true' || value === 'false') value = value === 'true';
    if (current === ELSEWHERE) continue;
    (current ?? out)[m[1]] = value;
  }
  return out;
}

const httpsOnly = (url, what) => {
  if (!/^https:\/\//i.test(String(url ?? ''))) {
    throw new AnchorError(`${what} must be an https URL, got ${url}`);
  }
  return String(url).replace(/\/+$/, '');
};

// ---------------------------------------------------------------- SEP-10

/**
 * Check a challenge really is a SEP-10 challenge for this account and anchor.
 *
 * This is the whole security of the flow. A challenge is a transaction, and a
 * transaction signed carelessly can move money. What makes a SEP-10 challenge
 * safe to sign is a set of properties that have to be checked, not assumed:
 * sequence number zero, so it can never be submitted; source is the anchor's own
 * signing key; the first operation is a manage_data whose source is *our*
 * account and whose key names the anchor's home domain; and the anchor has
 * already signed it, so the bytes came from the party the user chose to trust.
 *
 * Every one of those is checked here. Anything else is refused.
 */
/**
 * The raw bytes of each signature on a transaction.
 *
 * stellar-sdk has spelled this three ways: a `signature()` accessor in older
 * releases, a plain byte field, and in 17 an XDR wrapper whose bytes are under
 * `.value`. Getting it wrong is not a loud failure -- it reads as "the anchor
 * did not sign", which looks like a server problem and is not -- so it is
 * normalised here, once, where a test can see it.
 */
export function signaturesOf(tx) {
  return (tx.signatures ?? []).map((s) => {
    let raw = typeof s.signature === 'function' ? s.signature() : s.signature;
    if (raw && raw.byteLength === undefined && raw.value !== undefined) raw = raw.value;
    return raw ? Uint8Array.from(raw) : new Uint8Array();
  });
}

export function checkChallenge({ transaction, networkPassphrase, account, homeDomain, signingKey }) {
  let tx;
  try {
    tx = new Transaction(transaction, networkPassphrase);
  } catch (e) {
    throw new AnchorError(`The challenge is not a transaction: ${e.message}`);
  }
  if (tx.sequence !== '0') {
    throw new AnchorError(
      `A SEP-10 challenge must have sequence 0 so it can never be submitted; this one has ${tx.sequence}. Refusing to sign.`,
    );
  }
  if (tx.source !== signingKey) {
    throw new AnchorError(
      `The challenge is from ${tx.source}, but ${homeDomain} publishes ${signingKey} as its signing key. Refusing to sign.`,
    );
  }
  if (!tx.operations.length) throw new AnchorError('The challenge has no operations.');
  for (const [i, op] of tx.operations.entries()) {
    if (op.type !== 'manageData') {
      throw new AnchorError(`Operation ${i} is ${op.type}; a challenge may only manage data. Refusing to sign.`);
    }
  }
  const first = tx.operations[0];
  if (first.source !== account) {
    throw new AnchorError(
      `The challenge names ${first.source}, not ${account}. Refusing to sign something meant for another account.`,
    );
  }
  if (first.name !== `${homeDomain} auth`) {
    throw new AnchorError(`The challenge is for "${first.name}", not "${homeDomain} auth". Refusing to sign.`);
  }
  // The anchor signs its own challenge. Checking that proves these bytes came
  // from the anchor and were not made up by whatever relayed them here.
  const hash = tx.hash();
  const anchor = Keypair.fromPublicKey(signingKey);
  const signed = signaturesOf(tx).some((sig) => {
    // Narrow on purpose. A malformed signature should read as "not signed";
    // anything else is a bug in this file and should be loud about it.
    if (sig.length !== 64) return false;
    return anchor.verify(hash, sig);
  });
  if (!signed) {
    throw new AnchorError(`${homeDomain} has not signed its own challenge. Refusing to sign.`);
  }
  return { tx, hash, signature: signaturesOf(tx)[0], homeDomain, account };
}

// ---------------------------------------------------------------- the anchor

/**
 * Bind to an anchor by its home domain.
 *
 * @param {object} o
 * @param {string} o.homeDomain      e.g. "testanchor.stellar.org"
 * @param {function} [o.fetchImpl]   injected for tests
 */
export async function connectAnchor({ homeDomain, fetchImpl } = {}) {
  if (!homeDomain || /[^a-z0-9.-]/i.test(homeDomain)) {
    throw new AnchorError('Pass a home domain like "testanchor.stellar.org"');
  }
  const f = fetchImpl ?? globalThis.fetch;
  const tomlUrl = `https://${homeDomain}/.well-known/stellar.toml`;

  let tomlText;
  try {
    const res = await f(tomlUrl);
    if (!res.ok) throw new Error(`answered ${res.status}`);
    tomlText = await res.text();
  } catch (e) {
    throw new AnchorError(`No stellar.toml at ${homeDomain}: ${e.message}`);
  }
  const toml = parseToml(tomlText);

  const authUrl = httpsOnly(toml.WEB_AUTH_ENDPOINT, 'WEB_AUTH_ENDPOINT');
  const sep24 = httpsOnly(toml.TRANSFER_SERVER_SEP0024, 'TRANSFER_SERVER_SEP0024');
  const signingKey = String(toml.SIGNING_KEY ?? '');
  if (!GOOD_ACCOUNT.test(signingKey)) {
    throw new AnchorError(`${homeDomain} publishes no usable SIGNING_KEY`);
  }
  const networkPassphrase = toml.NETWORK_PASSPHRASE ?? Networks.TESTNET;

  const json = async (url, opts) => {
    const res = await f(url, opts);
    const text = await res.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      throw new AnchorError(`${url} did not answer with JSON`, text.slice(0, 200));
    }
    if (!res.ok) throw new AnchorError(body?.error ?? `${url} answered ${res.status}`, body);
    return body;
  };

  return {
    homeDomain,
    signingKey,
    networkPassphrase,
    authUrl,
    sep24,
    currencies: toml.currencies,

    /** What this anchor will take in and pay out, and the limits on each. */
    info: () => json(`${sep24}/info`),

    /** Step one of SEP-10: ask for a challenge and refuse anything that is not one. */
    async challenge(account) {
      if (!GOOD_ACCOUNT.test(account)) throw new AnchorError(`${account} is not a Stellar address`);
      const body = await json(
        `${authUrl}?account=${encodeURIComponent(account)}&home_domain=${encodeURIComponent(homeDomain)}`,
      );
      if (!body.transaction) throw new AnchorError('The anchor returned no challenge');
      const passphrase = body.network_passphrase ?? networkPassphrase;
      const { hash, signature } = checkChallenge({
        transaction: body.transaction,
        networkPassphrase: passphrase,
        account,
        homeDomain,
        signingKey,
      });
      return {
        transaction: body.transaction,
        networkPassphrase: passphrase,
        // What has to be signed, and who vouched for it. A wallet holding the
        // key can verify both without parsing a byte of XDR.
        hash: toHex(hash instanceof Uint8Array ? hash : new Uint8Array(hash)),
        anchorSignature: toHex(signature),
        signingKey,
        account,
        homeDomain,
      };
    },

    /** Step two: hand back the signed challenge, receive a session token. */
    async token({ transaction, networkPassphrase: passphrase, account, signatureHex }) {
      const tx = new Transaction(transaction, passphrase ?? networkPassphrase);
      tx.addSignature(account, toBase64(fromHex(signatureHex)));
      const body = await json(authUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ transaction: tx.toXDR() }),
      });
      if (!body.token) throw new AnchorError('The anchor returned no token', body);
      return body.token;
    },

    /**
     * SEP-10 end to end, with the signing left to someone else.
     *
     * `signHash` receives the 32 bytes to sign and returns 64 bytes of ed25519
     * signature. That indirection is the point: the key can stay in a browser,
     * or on a phone, and never pass through here.
     */
    async authenticate(account, signHash) {
      const c = await this.challenge(account);
      const sig = await signHash(fromHex(c.hash), c);
      const signatureHex = typeof sig === 'string' ? sig : toHex(new Uint8Array(sig));
      if (fromHex(signatureHex).length !== 64) {
        throw new AnchorError('A signature is 64 bytes');
      }
      return this.token({ ...c, signatureHex });
    },

    /**
     * Start a hosted deposit or withdrawal.
     *
     * Returns a URL the person opens to do the bank-side part: identity, account
     * details, whatever that anchor and that country require. None of that
     * belongs in this wallet, and it is a good thing that it does not.
     */
    async start(kind, { assetCode, token, account, amount, lang }) {
      if (kind !== 'deposit' && kind !== 'withdraw') {
        throw new AnchorError(`Unknown kind ${kind}`);
      }
      if (!assetCode) throw new AnchorError('Say which asset');
      if (!token) throw new AnchorError('Authenticate first');
      const body = await json(`${sep24}/transactions/${kind}/interactive`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: JSON.stringify({
          asset_code: assetCode,
          account,
          ...(amount ? { amount: String(amount) } : {}),
          ...(lang ? { lang } : {}),
        }),
      });
      if (!body.url || !body.id) throw new AnchorError('The anchor started nothing', body);
      return { url: body.url, id: body.id, type: body.type };
    },

    /** Where a deposit or withdrawal has got to. */
    async transaction(id, token) {
      const body = await json(`${sep24}/transaction?id=${encodeURIComponent(id)}`, {
        headers: { authorization: `Bearer ${token}` },
      });
      return body.transaction ?? body;
    },
  };
}
