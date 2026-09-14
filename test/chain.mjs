// What the online half must get right before it ever reaches a network.
//
// The parts that need a live chain are proved against testnet in the contracts
// repo's live run. These are the parts that must not need one: turning a
// contract error back into a reason, and refusing malformed input before it
// becomes a transaction someone pays for.

import assert from 'node:assert/strict';
import test from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';
import { connect, contractErrorCode } from '../src/chain.js';
import { LastmileError, ERRORS, TESTNET } from '../src/index.js';

const VAULT = 'CB5ZYVSQY2XF3BSCD4KMCQY2IJI23LQMTNBT3DO7Q4RKUDGTWDORWVPS';

test('a contract error is recovered from every envelope it arrives in', () => {
  assert.equal(contractErrorCode('HostError: Error(Contract, #6)'), 6);
  assert.equal(contractErrorCode(new Error('failed: Error(Contract, #10)')), 10);
  assert.equal(contractErrorCode({ error: 'Error(Contract, #3)' }), 3);
  assert.equal(contractErrorCode({ deep: { nested: 'Error(Contract, #7)' } }), 7);
  assert.equal(contractErrorCode('Error(Contract,#11)'), 11);
});

test('an unrelated failure is not mistaken for a contract error', () => {
  assert.equal(contractErrorCode(new Error('ECONNREFUSED')), null);
  assert.equal(contractErrorCode(undefined), null);
  assert.equal(contractErrorCode('Error(WasmVm, MissingValue)'), null);
});

test('a circular error object does not take the process down with it', () => {
  const e = new Error('Error(Contract, #4)');
  e.self = e;
  assert.equal(contractErrorCode(e), 4);
});

test('every contract error code has a sentence a person can read', () => {
  for (let code = 1; code <= 11; code++) {
    assert.ok(ERRORS[code], `code ${code} has no message`);
    assert.equal(new LastmileError(code).message, ERRORS[code]);
    assert.equal(new LastmileError(code).code, code);
  }
});

test('connecting needs a contract to connect to', () => {
  assert.throws(() => connect(), /contractId/);
  assert.throws(() => connect({}), /contractId/);
});

test('connect defaults to testnet and keeps what it was told', () => {
  const c = connect({ contractId: VAULT });
  assert.equal(c.contractId, VAULT);
  assert.equal(c.rpc, TESTNET.rpc);
  assert.equal(c.passphrase, TESTNET.passphrase);

  const custom = connect({ contractId: VAULT, rpc: 'http://localhost:8000', passphrase: 'Other' });
  assert.equal(custom.rpc, 'http://localhost:8000');
  assert.equal(custom.passphrase, 'Other');
});

test('the whole surface is there', () => {
  const c = connect({ contractId: VAULT });
  for (const m of ['vaultOf', 'isSpent', 'isDevice', 'wouldRedeem', 'redeem']) {
    assert.equal(typeof c[m], 'function', `${m} is missing`);
  }
});

test('a malformed key or signature is refused before any network call', async () => {
  const c = connect({ contractId: VAULT });
  const auth = {
    payer: Keypair.random().publicKey(),
    payee: Keypair.random().publicKey(),
    amount: '1',
    nonce: '1',
    expires: '9999999999',
  };
  // 31 bytes, not 32 — the sort of thing a truncated QR scan produces.
  await assert.rejects(
    () => c.redeem({ auth, device: 'aa'.repeat(31), sig: 'bb'.repeat(64) }, Keypair.random()),
    /32 bytes/,
  );
  await assert.rejects(
    () => c.redeem({ auth, device: 'aa'.repeat(32), sig: 'bb'.repeat(63) }, Keypair.random()),
    /64 bytes/,
  );
  await assert.rejects(
    () => c.redeem({ auth, device: 'not hex', sig: 'bb'.repeat(64) }, Keypair.random()),
    /hex/,
  );
});
