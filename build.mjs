#!/usr/bin/env node
// Assembles each evil napp from the shared chrome template + per-napp attacks.
// Zero dependencies. Output artifacts are the committed single-folder NAPP
// artifacts in napps/<id>/{index.html,metadata.json}, plus napps/manifest.json
// for the harness picker.
import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const src = join(root, 'src');
const template = readFileSync(join(src, 'chrome.template.html'), 'utf8');
const outDir = join(root, 'napps');

const MARK = '/*__ATTACKS__*/';
const IDS = { title: '__TITLE__', desc: '__DESC__', dtag: '__DTAG__' };

const manifest = [];
for (const id of readdirSync(join(src, 'napps')).sort()) {
  const dir = join(src, 'napps', id);
  if (!existsSync(join(dir, 'attacks.js'))) continue;
  const meta = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8'));
  let attacks = readFileSync(join(dir, 'attacks.js'), 'utf8').trim();
  if (attacks.includes('</script>')) throw new Error(id + ': attacks.js contains </script>');
  if (!/\bconst ATTACKS\b/.test(attacks)) throw new Error(id + ': attacks.js must define const ATTACKS');
  // The napp's own <meta name="description"> attribute gets the description
  // HTML-escaped — the RAW string stays in metadata.json, where it is the
  // attack vector (evil-02: metadata.json rendered as HTML by the launcher).
  const escAttr = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  const out = template
    .split(MARK).join(attacks + '\n')
    .split(IDS.title).join(meta.title)
    .split(IDS.desc).join(escAttr(meta.description))
    .split(IDS.dtag).join(meta.id)
    .replace('(function () {', "(function () {\n  window.__EVIL_ID__ = '" + meta.id + "';");
  if (out.includes(MARK) || out.includes('__TITLE__') || out.includes('__DESC__') || out.includes('__DTAG__')) {
    throw new Error(id + ': unresolved marker');
  }
  const target = join(outDir, id);
  mkdirSync(target, { recursive: true });
  writeFileSync(join(target, 'index.html'), out);
  // metadata.json next to index.html: the NAPP install shape (NAPP.md §Local
  // metadata). id is the d tag; requires/actions declared but empty here.
  const metadata = {
    id: meta.id,
    title: meta.title,
    ...(meta.icon ? { icon: meta.icon } : {}),
    description: meta.description,
    ...(meta.requires ? { requires: meta.requires } : { requires: [] }),
    ...(meta.actions ? { actions: meta.actions } : { actions: [] }),
  };
  writeFileSync(join(target, 'metadata.json'), JSON.stringify(metadata, null, 2) + '\n');
  manifest.push({ id: meta.id, title: meta.title });
  console.log('built napps/' + id + '/{index.html,metadata.json} (' + out.length + ' bytes)');
}

if (!manifest.length) throw new Error('no napps found under src/napps/');
writeFileSync(join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('built napps/manifest.json (' + manifest.length + ' napps)');
