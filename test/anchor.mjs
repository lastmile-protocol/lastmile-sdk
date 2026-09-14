// Tests for the anchor client.
//
// The one that matters is `checkChallenge`. SEP-10 asks a wallet to sign a
// transaction it did not build, which is exactly the shape of every key-theft
// story there is. So each refusal is tested by building the bad challenge for
// real -- with the same library an anchor would use -- and watching it be
// refused. A test that only checked the happy path would pass just as well
// against a function that checked nothing at all.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Account,
  Asset,
  BASE_FEE,
  Keypair,
  Networks,
  Operation,
  Transaction,
  TransactionBuilder,
} from '@stellar/stellar-sdk';

import { AnchorError, parseToml, checkChallenge, connectAnchor, signaturesOf } from '../src/anchor.js';
import { toHex, fromHex } from '../src/bytes.js';

const NET = Networks.TESTNET;
const HOME = 'anchor.example.org';

const anchorKp = Keypair.random();
const userKp = Keypair.random();
const SIGNING_KEY = anchorKp.publicKey();
const ACCOUNT = userKp.publicKey();

/** Build a challenge the way a correct anchor would, with knobs to break it. */
function buildChallenge({
  seq = '-1',
  source = anchorKp,
  opSource = ACCOUNT,
  name = `${HOME} auth`,
  sign = true,
  ops = null,
  extraWebAuth = true,
} = {}) {
  const builder = new TransactionBuilder(new Account(source.publicKey(), seq), {
    fee: BASE_FEE,
    networkPassphrase: NET,
  }).setTimeout(300);

  if (ops) {
    for (const op of ops) builder.addOperation(op);
  } else {
    builder.addOperation(
      Operation.manageData({
        name,
        value: Buffer.from(Keypair.random().rawPublicKey()).toString('base64').slice(0, 48),
        source: opSource,
      }),
    );
    if (extraWebAuth) {
      builder.addOperation(
        Operation.manageData({ name: 'web_auth_domain', value: HOME, source: SIGNING_KEY }),
      );
    }
  }
  const tx = builder.build();
  if (sign) tx.sign(source);
  return tx.toXDR();
}

const good = (over = {}) => ({
  transaction: buildChallenge(),
  networkPassphrase: NET,
  account: ACCOUNT,
  homeDomain: HOME,
  signingKey: SIGNING_KEY,
  ...over,
});

// ------------------------------------------------------------------ SEP-1

test('parseToml reads the fields a wallet needs', () => {
  const toml = parseToml(`
    # a comment
    VERSION="2.0.0"
    NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"
    SIGNING_KEY='${SIGNING_KEY}'
    WEB_AUTH_ENDPOINT = "https://anchor.example.org/auth"   # trailing comment
    TRANSFER_SERVER_SEP0024 = "https://anchor.example.org/sep24"

    [[CURRENCIES]]
    code = "USDC"
    issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

    [[CURRENCIES]]
    code = "SRT"
    is_asset_anchored = false

    [DOCUMENTATION]
    ORG_NAME = "Somebody Else"
  `);
  assert.equal(toml.VERSION, '2.0.0');
  assert.equal(toml.SIGNING_KEY, SIGNING_KEY);
  assert.equal(toml.WEB_AUTH_ENDPOINT, 'https://anchor.example.org/auth');
  assert.equal(toml.currencies.length, 2);
  assert.equal(toml.currencies[0].code, 'USDC');
  assert.equal(toml.currencies[1].is_asset_anchored, false);
  // Keys inside another table must not leak into the top level.
  assert.equal(toml.ORG_NAME, undefined);
});

test('parseToml survives an empty or junk document', () => {
  assert.deepEqual(parseToml('').currencies, []);
  assert.deepEqual(parseToml('<!doctype html><h1>404</h1>').currencies, []);
});

// ----------------------------------------------------------------- SEP-10

test('a well-formed challenge is accepted', () => {
  const out = checkChallenge(good());
  assert.equal(out.account, ACCOUNT);
  assert.equal(out.homeDomain, HOME);
  assert.equal(out.hash.length, 32);
});

test('a challenge with a real sequence number is refused', () => {
  // The whole reason a challenge is safe is that sequence 0 can never be
  // submitted. A challenge with a usable sequence is just a transaction.
  assert.throws(
    () => checkChallenge(good({ transaction: buildChallenge({ seq: '4000000000' }) })),
    (e) => e instanceof AnchorError && /sequence 0/.test(e.message),
  );
});

test('a challenge from someone other than the anchor is refused', () => {
  const impostor = Keypair.random();
  assert.throws(
    () => checkChallenge(good({ transaction: buildChallenge({ source: impostor }) })),
    (e) => e instanceof AnchorError && /signing key/.test(e.message),
  );
});

test('a challenge carrying a payment is refused', () => {
  // The attack this stops: an "anchor" whose challenge quietly moves money.
  const evil = buildChallenge({
    ops: [
      Operation.payment({
        destination: anchorKp.publicKey(),
        asset: Asset.native(),
        amount: '100',
        source: ACCOUNT,
      }),
    ],
  });
  assert.throws(
    () => checkChallenge(good({ transaction: evil })),
    (e) => e instanceof AnchorError && /may only manage data/.test(e.message),
  );
});

test('a challenge meant for another account is refused', () => {
  const someoneElse = Keypair.random().publicKey();
  assert.throws(
    () => checkChallenge(good({ transaction: buildChallenge({ opSource: someoneElse }) })),
    (e) => e instanceof AnchorError && /Refusing to sign something meant for another account/.test(e.message),
  );
});

test('a challenge for a different home domain is refused', () => {
  // Domain confusion: a token minted for evil.example is not a token for us.
  assert.throws(
    () => checkChallenge(good({ transaction: buildChallenge({ name: 'evil.example auth' }) })),
    (e) => e instanceof AnchorError && /"evil.example auth"/.test(e.message),
  );
});

test('a challenge the anchor has not signed is refused', () => {
  assert.throws(
    () => checkChallenge(good({ transaction: buildChallenge({ sign: false }) })),
    (e) => e instanceof AnchorError && /has not signed its own challenge/.test(e.message),
  );
});

test('a challenge signed by the wrong key is refused', () => {
  const impostor = Keypair.random();
  const tx = buildChallenge({ sign: false });
  const parsed = new Transaction(tx, NET);
  parsed.sign(impostor);
  assert.throws(
    () => checkChallenge(good({ transaction: parsed.toXDR() })),
    (e) => e instanceof AnchorError && /has not signed its own challenge/.test(e.message),
  );
});

test('something that is not a transaction is refused', () => {
  assert.throws(
    () => checkChallenge(good({ transaction: 'not xdr at all' })),
    (e) => e instanceof AnchorError && /not a transaction/.test(e.message),
  );
});

test('signaturesOf returns 64 raw bytes whatever shape the sdk uses', () => {
  // A regression guard. The first version of this file read the signature the
  // wrong way and every challenge came back "unsigned" -- a failure that looks
  // like the anchor's fault and is not.
  const tx = new Transaction(buildChallenge(), NET);
  const sigs = signaturesOf(tx);
  assert.equal(sigs.length, 1);
  assert.ok(sigs[0] instanceof Uint8Array);
  assert.equal(sigs[0].length, 64);
});

// ----------------------------------------------------------------- SEP-24

const TOML = `
VERSION="2.0.0"
NETWORK_PASSPHRASE="${NET}"
SIGNING_KEY="${SIGNING_KEY}"
WEB_AUTH_ENDPOINT="https://${HOME}/auth/"
TRANSFER_SERVER_SEP0024="https://${HOME}/sep24"

[[CURRENCIES]]
code="USDC"
`;

/** A fetch that answers from a table of routes and records what it was asked. */
function fakeFetch(routes) {
  const calls = [];
  const f = async (url, opts = {}) => {
    calls.push({ url: String(url), opts });
    for (const [pattern, reply] of routes) {
      if (String(url).includes(pattern)) {
        const r = typeof reply === 'function' ? await reply(String(url), opts) : reply;
        return {
          ok: r.status === undefined || (r.status >= 200 && r.status < 300),
          status: r.status ?? 200,
          text: async () => (typeof r.body === 'string' ? r.body : JSON.stringify(r.body)),
        };
      }
    }
    throw new Error(`no route for ${url}`);
  };
  f.calls = calls;
  return f;
}

const baseRoutes = () => [['/.well-known/stellar.toml', { body: TOML }]];

test('connectAnchor reads the toml and exposes the endpoints', async () => {
  const a = await connectAnchor({ homeDomain: HOME, fetchImpl: fakeFetch(baseRoutes()) });
  assert.equal(a.signingKey, SIGNING_KEY);
  assert.equal(a.networkPassphrase, NET);
  assert.equal(a.authUrl, `https://${HOME}/auth`); // trailing slash trimmed
  assert.equal(a.sep24, `https://${HOME}/sep24`);
  assert.deepEqual(a.currencies, [{ code: 'USDC' }]);
});

test('an anchor that offers a plain-http endpoint is refused', async () => {
  const routes = [['/.well-known/stellar.toml', { body: TOML.replace('https://' + HOME + '/auth/', 'http://' + HOME + '/auth') }]];
  await assert.rejects(
    () => connectAnchor({ homeDomain: HOME, fetchImpl: fakeFetch(routes) }),
    (e) => e instanceof AnchorError && /must be an https URL/.test(e.message),
  );
});

test('an anchor with no signing key is refused', async () => {
  const routes = [['/.well-known/stellar.toml', { body: TOML.replace(/SIGNING_KEY=.*/, 'SIGNING_KEY="nope"') }]];
  await assert.rejects(
    () => connectAnchor({ homeDomain: HOME, fetchImpl: fakeFetch(routes) }),
    (e) => e instanceof AnchorError && /no usable SIGNING_KEY/.test(e.message),
  );
});

test('a home domain that is not one is refused before any request', async () => {
  await assert.rejects(
    () => connectAnchor({ homeDomain: 'https://evil.example/path' }),
    (e) => e instanceof AnchorError && /home domain/.test(e.message),
  );
});

test('info passes the anchor limits through', async () => {
  const a = await connectAnchor({
    homeDomain: HOME,
    fetchImpl: fakeFetch([
      ...baseRoutes(),
      ['/sep24/info', { body: { deposit: { USDC: { enabled: true, min_amount: 1 } }, withdraw: {} } }],
    ]),
  });
  const info = await a.info();
  assert.equal(info.deposit.USDC.min_amount, 1);
});

test('challenge hands back the hash and the anchor signature as hex', async () => {
  const a = await connectAnchor({
    homeDomain: HOME,
    fetchImpl: fakeFetch([
      ...baseRoutes(),
      ['/auth?', { body: { transaction: buildChallenge(), network_passphrase: NET } }],
    ]),
  });
  const c = await a.challenge(ACCOUNT);
  assert.equal(fromHex(c.hash).length, 32);
  assert.equal(fromHex(c.anchorSignature).length, 64);
  assert.equal(c.account, ACCOUNT);
  // The wallet can check the anchor vouched for exactly these bytes without
  // ever parsing XDR. That is the point of handing both back.
  assert.ok(anchorKp.verify(Buffer.from(fromHex(c.hash)), Buffer.from(fromHex(c.anchorSignature))));
});

test('challenge refuses a bad challenge from a real anchor endpoint', async () => {
  const a = await connectAnchor({
    homeDomain: HOME,
    fetchImpl: fakeFetch([
      ...baseRoutes(),
      ['/auth?', { body: { transaction: buildChallenge({ seq: '99' }), network_passphrase: NET } }],
    ]),
  });
  await assert.rejects(() => a.challenge(ACCOUNT), (e) => /sequence 0/.test(e.message));
});

test('challenge refuses an address that is not one without calling out', async () => {
  const f = fakeFetch(baseRoutes());
  const a = await connectAnchor({ homeDomain: HOME, fetchImpl: f });
  const before = f.calls.length;
  await assert.rejects(() => a.challenge('not-an-address'), (e) => /not a Stellar address/.test(e.message));
  assert.equal(f.calls.length, before, 'it should not have gone to the network');
});

test('authenticate signs the hash it was given and gets a token', async () => {
  let posted = null;
  const f = fakeFetch([
    ...baseRoutes(),
    ['/auth?', { body: { transaction: buildChallenge(), network_passphrase: NET } }],
    [
      `https://${HOME}/auth`,
      (url, opts) => {
        posted = JSON.parse(opts.body);
        return { body: { token: 'jwt.for.you' } };
      },
    ],
  ]);
  const a = await connectAnchor({ homeDomain: HOME, fetchImpl: f });

  let sawHash = null;
  const token = await a.authenticate(ACCOUNT, (hash) => {
    sawHash = hash;
    // Exactly what a browser-held key would do: sign 32 bytes, return 64.
    return new Uint8Array(userKp.sign(Buffer.from(hash)));
  });

  assert.equal(token, 'jwt.for.you');
  assert.equal(sawHash.length, 32);

  // The posted transaction must carry both signatures: the anchor's and ours.
  const signed = new Transaction(posted.transaction, NET);
  assert.equal(signed.signatures.length, 2);
  const sigs = signaturesOf(signed);
  assert.ok(sigs.some((s) => userKp.verify(Buffer.from(signed.hash()), Buffer.from(s))));
  assert.ok(sigs.some((s) => anchorKp.verify(Buffer.from(signed.hash()), Buffer.from(s))));
});

test('authenticate refuses a signature that is not 64 bytes', async () => {
  const a = await connectAnchor({
    homeDomain: HOME,
    fetchImpl: fakeFetch([
      ...baseRoutes(),
      ['/auth?', { body: { transaction: buildChallenge(), network_passphrase: NET } }],
    ]),
  });
  await assert.rejects(
    () => a.authenticate(ACCOUNT, () => new Uint8Array(32)),
    (e) => e instanceof AnchorError && /64 bytes/.test(e.message),
  );
});

test('start opens an interactive deposit', async () => {
  let sent = null;
  let auth = null;
  const a = await connectAnchor({
    homeDomain: HOME,
    fetchImpl: fakeFetch([
      ...baseRoutes(),
      [
        '/transactions/deposit/interactive',
        (url, opts) => {
          sent = JSON.parse(opts.body);
          auth = opts.headers.authorization;
          return { body: { type: 'interactive_customer_info_needed', url: 'https://anchor.example.org/i/abc', id: 'tx-1' } };
        },
      ],
    ]),
  });
  const out = await a.start('deposit', { assetCode: 'USDC', token: 'jwt', account: ACCOUNT, amount: 25 });
  assert.equal(out.id, 'tx-1');
  assert.equal(out.url, 'https://anchor.example.org/i/abc');
  assert.equal(sent.asset_code, 'USDC');
  assert.equal(sent.amount, '25');
  assert.equal(auth, 'Bearer jwt');
});

test('start refuses an unknown kind, a missing asset and a missing token', async () => {
  const a = await connectAnchor({ homeDomain: HOME, fetchImpl: fakeFetch(baseRoutes()) });
  await assert.rejects(() => a.start('sideways', { assetCode: 'USDC', token: 't' }), /Unknown kind/);
  await assert.rejects(() => a.start('withdraw', { token: 't' }), /which asset/);
  await assert.rejects(() => a.start('withdraw', { assetCode: 'USDC' }), /Authenticate first/);
});

test('an anchor error is reported with the anchor words, not a status code', async () => {
  const a = await connectAnchor({
    homeDomain: HOME,
    fetchImpl: fakeFetch([
      ...baseRoutes(),
      ['/transactions/withdraw/interactive', { status: 403, body: { error: 'This account is not allowed to withdraw' } }],
    ]),
  });
  await assert.rejects(
    () => a.start('withdraw', { assetCode: 'USDC', token: 'jwt', account: ACCOUNT }),
    (e) => e instanceof AnchorError && e.message === 'This account is not allowed to withdraw',
  );
});

test('an anchor that answers html is reported as such', async () => {
  const a = await connectAnchor({
    homeDomain: HOME,
    fetchImpl: fakeFetch([...baseRoutes(), ['/sep24/info', { body: '<html>502 Bad Gateway</html>' }]]),
  });
  await assert.rejects(() => a.info(), (e) => e instanceof AnchorError && /did not answer with JSON/.test(e.message));
});

test('transaction reports where a withdrawal has got to', async () => {
  const a = await connectAnchor({
    homeDomain: HOME,
    fetchImpl: fakeFetch([
      ...baseRoutes(),
      ['/sep24/transaction?id=', { body: { transaction: { id: 'tx-1', status: 'pending_user_transfer_start', amount_in: '25' } } }],
    ]),
  });
  const t = await a.transaction('tx-1', 'jwt');
  assert.equal(t.status, 'pending_user_transfer_start');
  assert.equal(t.amount_in, '25');
});

// ------------------------------------------------- against the real thing

test("the parser handles the SDF test anchor's actual stellar.toml", async () => {
  // A recorded fixture, not a live call. The point is that the parser has met a
  // document an anchor really serves -- with ACCOUNTS arrays, a KYC_SERVER, a
  // DOCUMENTATION table and three currencies -- and not only ones I wrote.
  const { readFileSync } = await import('node:fs');
  const text = readFileSync(new URL('./fixtures/testanchor.toml', import.meta.url), 'utf8');
  const toml = parseToml(text);
  assert.equal(toml.SIGNING_KEY, 'GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR');
  assert.equal(toml.NETWORK_PASSPHRASE, 'Test SDF Network ; September 2015');
  assert.equal(toml.WEB_AUTH_ENDPOINT, 'https://testanchor.stellar.org/auth');
  assert.equal(toml.TRANSFER_SERVER_SEP0024, 'https://testanchor.stellar.org/sep24');
  assert.deepEqual(toml.currencies.map((c) => c.code), ['SRT', 'USDC', 'native']);
  assert.equal(toml.currencies[0].is_asset_anchored, false);
  // DOCUMENTATION lives in its own table and must not have leaked upward.
  assert.equal(toml.ORG_NAME, undefined);
});

test('connectAnchor binds to the SDF test anchor document end to end', async () => {
  const { readFileSync } = await import('node:fs');
  const text = readFileSync(new URL('./fixtures/testanchor.toml', import.meta.url), 'utf8');
  const a = await connectAnchor({
    homeDomain: 'testanchor.stellar.org',
    fetchImpl: fakeFetch([['/.well-known/stellar.toml', { body: text }]]),
  });
  assert.equal(a.signingKey, 'GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR');
  assert.equal(a.sep24, 'https://testanchor.stellar.org/sep24');
  assert.equal(a.networkPassphrase, 'Test SDF Network ; September 2015');
});
