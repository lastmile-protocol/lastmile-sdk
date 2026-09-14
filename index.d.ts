/// <reference types="node" />
import type { Buffer } from 'node:buffer';
import type { Keypair } from '@stellar/stellar-sdk';

/** Network configuration parameters for Stellar/Soroban RPC. */
export interface NetworkConfig {
  rpc: string;
  passphrase: string;
}

export const TESTNET: NetworkConfig;

/** Human-readable error messages for Soroban contract error codes. */
export const ERRORS: Record<number, string>;

/** Error thrown when contract execution or voucher validation fails. */
export class LastmileError extends Error {
  readonly code: number;
  constructor(code: number, detail?: string);
}

/**
 * An offline-authorized payment on Stellar.
 *
 * Notice: `amount` and `nonce` are typed strictly as `string | bigint`.
 * Passing a `number` is rejected to prevent silent precision loss beyond JS SafeInteger limits.
 */
export interface Authorization {
  payer: string;
  payee: string;
  amount: string | bigint;
  nonce: string | bigint;
  expires: string | bigint;
}

/** A signed voucher carrying authorization, public device key, and signature. */
export interface Voucher {
  auth: Authorization;
  device: string;
  sig: string;
}

/** Wire format length in bytes for packed vouchers. */
export const PACKED_BYTES: number;

/** Encode an Authorization as an XDR ScVal map with sorted symbol keys. */
export function encode(auth: Authorization): Buffer;

/** Compute the 32-byte sha256 payload signed by the device. */
export function payload(auth: Authorization): Buffer;

/** Sign an authorization offline using a Stellar secret seed or Keypair. */
export function sign(auth: Authorization, device: string | Keypair): Voucher;

/** Check a voucher's signature locally without network connectivity. */
export function verify(voucher: Voucher): boolean;

/** Pack a voucher into base64url wire format (184 bytes). */
export function pack(v: Voucher): string;

/** Unpack a voucher from its base64url wire format. */
export function unpack(s: string): Voucher;
