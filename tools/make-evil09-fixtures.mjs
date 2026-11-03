// Regenerates evil-09's manifest fixtures — committed artifacts, like the
// rest of napps/. Three REAL kind 35130 manifests:
//
//   manifest-v1.json        the older version, by the author (real BIP340 sig)
//   manifest-v2.json        the NEWEST version, by the author (real BIP340 sig)
//   manifest-attacker.json  a hostile-relay clone: same d tag, NEWEST
//                           created_at of all, by a DIFFERENT key
//
// plus blobs/ (the file bytes each manifest's path tags name, by sha256)
// and author-pubkey.txt (what the harness's fetchManifest miniature binds
// by). The napp's built index.html carries a version marker comment
// (see src/napps/evil-09-manifest-rollback/attacks.js); v1 and the attacker
// clone are the same built bytes with the marker rewritten, so a rolled-back
// frame can tell which manifest installed it — the ONLY thing in this whole
// pipeline that can tell, which is the finding.
//
// Deterministic: fixed created_at values, fixed seeds, zero aux randomness —
// rebuilds reproduce byte-identical fixtures.
//
// Run standalone (after `node build.mjs`):  node tools/make-evil09-fixtures.mjs
// Also invoked automatically at the end of build.mjs.
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { schnorrSign, schnorrVerify, eventId, sha256Hex, pubkeyFromSecret } from './bip340.mjs';

const NAPP_ID = 'evil-09-manifest-rollback';
// must match the marker comment in src/napps/evil-09-manifest-rollback/attacks.js
const MARKER = 'manifest-version: evil09:v2';
const AUTHOR_SEED = 'evil-09 manifest fixture author (deterministic test key, never a real key)';
const ATTACKER_SEED = 'evil-09 hostile-relay attacker (deterministic test key, never a real key)';
// fixed timestamps so rebuilds are identical
const T_V1 = 1735689600;        // 2025-01-01T00:00:00Z — the older version
const T_V2 = 1735776000;        // 2025-01-02T00:00:00Z — the newest version
const T_ATTACKER = 1735862400;  // 2025-01-03T00:00:00Z — newest of ALL

const toolDir = dirname(fileURLToPath(import.meta.url));

function manifestEvent(secret, { version, created, indexSha, metaSha, title }) {
  const { pubHex } = pubkeyFromSecret(secret);
  const tags = [
    ['d', NAPP_ID],
    ['title', title],
    ['version', version],
    ['path', '/index.html', indexSha, 'text/html'],
    ['path', '/metadata.json', metaSha, 'application/json'],
  ];
  const ev = { pubkey: pubHex, created_at: created, kind: 35130, tags, content: '' };
  ev.id = eventId(ev);
  ev.sig = schnorrSign(Buffer.from(ev.id, 'hex'), secret);
  if (!schnorrVerify(Buffer.from(ev.id, 'hex'), pubHex, ev.sig)) {
    throw new Error('fixture ' + version + ' failed self-verification');
  }
  return ev;
}

export function makeFixtures(outDir) {
  const nappDir = join(outDir, NAPP_ID);
  const builtText = readFileSync(join(nappDir, 'index.html'), 'utf8');
  if (!builtText.includes(MARKER)) {
    throw new Error(NAPP_ID + ': built index.html lacks the "' + MARKER + '" marker comment');
  }
  const metaBuf = readFileSync(join(nappDir, 'metadata.json'));

  // same bytes, different version marker — each manifest's path tags name
  // its own index.html by sha256, so the blobs differ per version
  const bytes = {
    v2: Buffer.from(builtText, 'utf8'),
    v1: Buffer.from(builtText.split(MARKER).join('manifest-version: evil09:v1'), 'utf8'),
    attacker: Buffer.from(builtText.split(MARKER).join('manifest-version: evil09:attacker'), 'utf8'),
    meta: metaBuf,
  };
  const sha = {};
  for (const [k, b] of Object.entries(bytes)) sha[k] = sha256Hex(b);

  const authorSecret = BigInt('0x' + sha256Hex(Buffer.from(AUTHOR_SEED)));
  const attackerSecret = BigInt('0x' + sha256Hex(Buffer.from(ATTACKER_SEED)));

  const v1 = manifestEvent(authorSecret, {
    version: 'v1', created: T_V1, indexSha: sha.v1, metaSha: sha.meta,
    title: 'evil-09 manifest rollback',
  });
  const v2 = manifestEvent(authorSecret, {
    version: 'v2', created: T_V2, indexSha: sha.v2, metaSha: sha.meta,
    title: 'evil-09 manifest rollback',
  });
  const attacker = manifestEvent(attackerSecret, {
    version: 'attacker-v3', created: T_ATTACKER, indexSha: sha.attacker, metaSha: sha.meta,
    title: 'evil-09 manifest rollback', // lookalike: the takeover's whole claim
  });

  const fx = join(nappDir, 'fixtures');
  rmSync(fx, { recursive: true, force: true });
  mkdirSync(join(fx, 'blobs'), { recursive: true });
  writeFileSync(join(fx, 'manifest-v1.json'), JSON.stringify(v1, null, 2) + '\n');
  writeFileSync(join(fx, 'manifest-v2.json'), JSON.stringify(v2, null, 2) + '\n');
  writeFileSync(join(fx, 'manifest-attacker.json'), JSON.stringify(attacker, null, 2) + '\n');
  const { pubHex: authorPub } = pubkeyFromSecret(authorSecret);
  writeFileSync(join(fx, 'author-pubkey.txt'), authorPub + '\n');
  for (const [k, b] of Object.entries(bytes)) writeFileSync(join(fx, 'blobs', sha[k]), b);

  return {
    authorPub,
    fixtures: {
      v1: { id: v1.id, created_at: T_V1 },
      v2: { id: v2.id, created_at: T_V2 },
      attacker: { id: attacker.id, created_at: T_ATTACKER, pubkey: attacker.pubkey },
    },
  };
}

// CLI
if (process.argv[1] && fileURLToPath(import.meta.url) === (await import('node:path')).resolve(process.argv[1])) {
  const root = join(toolDir, '..');
  const out = join(root, 'napps');
  const made = makeFixtures(out);
  console.log('regenerated napps/' + NAPP_ID + '/fixtures/ (author ' + made.authorPub.slice(0, 16) + '…)');
  for (const [k, v] of Object.entries(made.fixtures)) {
    console.log('  ' + k.padEnd(8) + ' id=' + v.id.slice(0, 16) + '… created_at=' + v.created_at);
  }
}
