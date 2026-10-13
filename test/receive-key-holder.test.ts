import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, createPublicKey, generateKeyPairSync, publicEncrypt } from 'node:crypto';
import { keyHolderFromKey } from '../src/receive/key-holder.js';
import { createTestPki } from './helpers/pki.js';

test('keyHolderFromKey unwraps an RSA-OAEP(SHA-256) session key', async () => {
  const pki = createTestPki();
  const holder = keyHolderFromKey(pki.receiver.keyObject, pki.receiver.certPem);
  const sessionKey = Buffer.alloc(16, 7);
  const wrapped = publicEncrypt(
    { key: pki.receiver.certPem, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING },
    sessionKey,
  );
  const unwrapped = await holder.unwrap(wrapped);
  assert.ok(Buffer.from(unwrapped).equals(sessionKey), 'the unwrapped key must match');
  assert.equal(holder.certificate, pki.receiver.certPem);
});

test('keyHolderFromKey refuses a public key', () => {
  const pki = createTestPki();
  assert.throws(() => keyHolderFromKey(createPublicKey(pki.receiver.certPem), pki.receiver.certPem), /private key/);
});

test('keyHolderFromKey refuses a non-RSA key', () => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  assert.throws(() => keyHolderFromKey(privateKey, 'unused'), /RSA key/);
});
