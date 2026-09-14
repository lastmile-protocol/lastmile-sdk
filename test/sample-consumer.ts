import type { Buffer } from 'node:buffer';
import {
  Authorization,
  Voucher,
  LastmileError,
  TESTNET,
  ERRORS,
  PACKED_BYTES,
  encode,
  payload,
  sign,
  verify,
  pack,
  unpack,
} from '../index.js';

// 1. Valid authorization with string / bigint values
const auth1: Authorization = {
  payer: 'GD...',
  payee: 'GC...',
  amount: '1000000',
  nonce: 18446744073709551615n,
  expires: '1789393424',
};

const encoded: Buffer = encode(auth1);
const hashedPayload: Buffer = payload(auth1);
const voucher: Voucher = sign(auth1, 'S...');
const isValid: boolean = verify(voucher);
const packed: string = pack(voucher);
const unpacked: Voucher = unpack(packed);

const err = new LastmileError(1);
const code: number = err.code;
const rpcUrl: string = TESTNET.rpc;
const errorMsg: string | undefined = ERRORS[1];
const bytes: number = PACKED_BYTES;

// Type verification tests:
const invalidAmount: Authorization = {
  payer: 'GD...',
  payee: 'GC...',
  // @ts-expect-error number cannot be passed to amount
  amount: 1000000,
  nonce: '1',
  expires: '1000',
};

const invalidNonce: Authorization = {
  payer: 'GD...',
  payee: 'GC...',
  amount: '1000000',
  // @ts-expect-error number cannot be passed to nonce
  nonce: 1,
  expires: '1000',
};
