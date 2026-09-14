// The half that needs a network.
//
// Everything in ./index.js works with the radio off. This file is the other
// side of the split: taking a voucher someone signed hours ago in a place with
// no signal and settling it on Stellar. It is a separate import so that a wallet
// which only ever signs never has to load an RPC client it will not use.
//
// Redemption is permissionless in the contract -- the signature is the authority,
// not the sender -- but a Stellar transaction still needs a source account to pay
// the fee. That account is the `submitter` here. It authorises nothing about the
// payment; it buys the ledger space.

import {
  Account,
  BASE_FEE,
  Contract,
  Keypair,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  scValToNative,
  xdr,
} from '@stellar/stellar-sdk';
import { LastmileError, TESTNET, toScVal } from './index.js';
import { fromHex } from './bytes.js';

/**
 * Pull `Error(Contract, #7)` out of whatever shape the failure arrived in.
 *
 * Soroban surfaces contract errors as text buried in several different envelopes
 * depending on whether simulation, submission or the final result rejected them.
 * Recovering the number turns all of that back into a reason a person can read.
 */
export function contractErrorCode(e) {
  let text = typeof e === 'string' ? e : (e?.message ?? '');
  if (typeof e === 'object' && e !== null) {
    try {
      // Errors carry structure as well as a message, and the code is sometimes
      // only in the structure. Circular objects are not worth a crash here.
      text += ' ' + JSON.stringify(e);
    } catch {
      /* not serialisable; the message alone will have to do */
    }
  }
  const m = /Error\(Contract,\s*#(\d+)\)/.exec(text);
  return m ? Number(m[1]) : null;
}

function rethrow(e, what) {
  const code = contractErrorCode(e);
  if (code !== null) throw new LastmileError(code);
  throw new Error(`${what}: ${e?.message ?? e}`);
}

const bytesN = (hex, n, what) => {
  const b = fromHex(hex);
  if (b.length !== n) throw new TypeError(`${what} should be ${n} bytes, got ${b.length}`);
  return xdr.ScVal.scvBytes(b);
};

/**
 * Bind to a deployed vault.
 *
 * @param {object} o
 * @param {string} o.contractId    the vault's contract address
 * @param {string} [o.rpc]         Soroban RPC URL
 * @param {string} [o.passphrase]  network passphrase
 * @param {string} [o.fee]         max fee in stroops
 */
export function connect({
  contractId,
  rpc: url = TESTNET.rpc,
  passphrase = TESTNET.passphrase,
  fee = BASE_FEE,
  timeoutSeconds = 30,
  pollMs = 1000,
  pollFor = 30_000,
} = {}) {
  if (!contractId) throw new TypeError('connect needs a contractId');
  const server = new rpc.Server(url, { allowHttp: url.startsWith('http://') });
  const contract = new Contract(contractId);

  // Reads are simulated, never submitted, so the source account is a formality:
  // it is never charged, never signs, and need not exist. A fresh key avoids
  // borrowing someone else's sequence number by accident.
  const readSource = () => new Account(Keypair.random().publicKey(), '0');

  const build = (account, ...args) =>
    new TransactionBuilder(account, { fee, networkPassphrase: passphrase })
      .addOperation(contract.call(...args))
      .setTimeout(timeoutSeconds)
      .build();

  /** Simulate a call and hand back its native return value. */
  async function read(method, ...args) {
    const sim = await server.simulateTransaction(build(readSource(), method, ...args));
    if (rpc.Api.isSimulationError(sim)) rethrow(sim.error, method);
    if (!sim.result?.retval) throw new Error(`${method}: simulation returned nothing`);
    return scValToNative(sim.result.retval);
  }

  const addr = (a) => nativeToScVal(a, { type: 'address' });

  return {
    contractId,
    rpc: url,
    passphrase,

    /** A payer's float and bond, or a LastmileError if they have no vault. */
    vaultOf: (payer) => read('vault_of', addr(payer)),

    /** Has this nonce already been redeemed? */
    isSpent: (payer, nonce) =>
      read('is_spent', addr(payer), nativeToScVal(BigInt(nonce), { type: 'u64' })),

    /** May this key still sign for this payer? Revoked keys answer false. */
    isDevice: (payer, deviceHex) =>
      read('is_device', addr(payer), bytesN(deviceHex, 32, 'device key')),

    /**
     * Would this voucher be paid right now?
     *
     * For a payee with a moment of signal and a long walk home: it costs nothing,
     * submits nothing, and answers before they hand over the goods. The contract
     * panics rather than returning false on a bad signature, so a failed
     * simulation is simply "no".
     */
    async wouldRedeem(voucher) {
      try {
        return await read(
          'would_redeem',
          toScVal(voucher.auth),
          bytesN(voucher.device, 32, 'device key'),
          bytesN(voucher.sig, 64, 'signature'),
        );
      } catch {
        return false;
      }
    },

    /**
     * Settle a voucher on chain.
     *
     * @param voucher   from `unpack`, or straight from `sign`
     * @param submitter a Keypair or secret seed that pays the fee
     * @returns {Promise<{hash: string, ledger: number}>}
     */
    async redeem(voucher, submitter) {
      // Check the voucher before anything reaches the network. A truncated scan
      // or a mistyped key should fail here, instantly and for free, rather than
      // after a round trip that costs the submitter time and a fee estimate.
      const device = bytesN(voucher?.device, 32, 'device key');
      const sig = bytesN(voucher?.sig, 64, 'signature');
      const auth = toScVal(voucher.auth);

      const kp = typeof submitter === 'string' ? Keypair.fromSecret(submitter) : submitter;
      let account;
      try {
        account = await server.getAccount(kp.publicKey());
      } catch (e) {
        throw new Error(
          `the submitting account ${kp.publicKey()} is not funded on this network ` +
            `(${e?.message ?? e}). Redeeming costs a Stellar fee, which someone has to pay.`,
        );
      }

      const tx = build(account, 'redeem', auth, device, sig);

      // prepareTransaction simulates first, so a voucher that cannot be paid
      // fails here for free rather than costing a fee to find out.
      let prepared;
      try {
        prepared = await server.prepareTransaction(tx);
      } catch (e) {
        rethrow(e, 'redeem');
      }
      prepared.sign(kp);

      const sent = await server.sendTransaction(prepared);
      if (sent.status === 'ERROR') {
        rethrow(sent.errorResult ?? sent, 'redeem');
      }

      const deadline = Date.now() + pollFor;
      for (;;) {
        const got = await server.getTransaction(sent.hash);
        if (got.status === rpc.Api.GetTransactionStatus.SUCCESS) {
          return { hash: sent.hash, ledger: got.ledger };
        }
        if (got.status === rpc.Api.GetTransactionStatus.FAILED) {
          rethrow(got.resultXdr?.toXDR?.('base64') ?? got, 'redeem');
        }
        if (Date.now() > deadline) {
          throw new Error(
            `redeem was submitted as ${sent.hash} but has not appeared after ` +
              `${Math.round(pollFor / 1000)}s. It may still land; check the hash before retrying.`,
          );
        }
        await new Promise((r) => setTimeout(r, pollMs));
      }
    },
  };
}
