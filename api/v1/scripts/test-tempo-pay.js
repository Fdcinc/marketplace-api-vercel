/**
 * Simple Tempo payment test client (Windows-friendly)
 * Usage: node test-tempo-pay.js
 */
const { privateKeyToAccount } = require('viem/accounts');
const { Mppx, tempo } = require('mppx/client');

// 1. Put a Tempo testnet private key here (or generate one)
//    NEVER commit a real key. For testnet only.
const PRIVATE_KEY = process.env.TEMPO_TEST_PRIVATE_KEY || '0xYOUR_TESTNET_PRIVATE_KEY';

if (PRIVATE_KEY.includes('YOUR_TESTNET')) {
  console.error('Set TEMPO_TEST_PRIVATE_KEY in .env or replace the placeholder.');
  process.exit(1);
}

const account = privateKeyToAccount(PRIVATE_KEY);

const mppx = Mppx.create({
  methods: [tempo({ account })],
  polyfill: false, // don't touch global fetch
});

async function main() {
  const url = 'http://localhost:5000/api/v1/mpp/premium';
  console.log('→ Requesting', url);

  const res = await mppx.fetch(url);
  console.log('Status:', res.status);
  console.log('Body:', await res.text());
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});