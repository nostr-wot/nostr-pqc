// Deterministic size model, not encryption or signature test vectors.
import assert from 'node:assert/strict';
const bytes = value => Buffer.byteLength(typeof value === 'string' ? value : JSON.stringify(value));
const b64 = n => 'A'.repeat(4 * Math.ceil(n / 3));
function padded(n) {
  assert(n > 0);
  if (n <= 32) return 32;
  const next = 2 ** (Math.floor(Math.log2(n - 1)) + 1);
  const chunk = next <= 256 ? 32 : next / 8;
  return chunk * Math.ceil(n / chunk);
}
const classical = n => b64(65 + (n < 65536 ? 2 : 6) + padded(n));
const hybrid = n => { assert(n <= 65535); return b64(1612 + padded(n)); };
const event = (kind, content, tags = []) => ({pubkey:'a'.repeat(64),created_at:1789128000,kind,tags,content,id:'b'.repeat(64),sig:'c'.repeat(128)});
const wire = e => bytes(['EVENT',e]);
function dm(n, pq) {
 const rumor = event(14,'x'.repeat(n),[['p','d'.repeat(64)]]); delete rumor.sig;
 const inner = bytes(rumor);
 const seal = event(13,pq ? hybrid(inner) : classical(inner));
 const sealBytes = bytes(seal);
 const wrap = event(1059,classical(sealBytes),[['p','d'.repeat(64)]]);
 return {wire:wire(wrap),rumor:inner,seal:sealBytes,legacyOuterFits:sealBytes <= 65535};
}
const rows = [1,32,280,1024,4096,16384,32000].map(n => {
 const a=dm(n,false),b=dm(n,true);
 return {text_bytes:n,classical_wire:a.wire,hybrid_wire:b.wire,extra_bytes:b.wire-a.wire,ratio:Number((b.wire/a.wire).toFixed(2))};
});
const base=event(1,'x'.repeat(280));
const proof=['pq','nostr-wot/hybrid-event/1','d'.repeat(64),b64(4628)];
const signed={...base,tags:[proof]};
const attestation=event(10203,'',[
 ['alg','ml-kem-1024',b64(1568)],['alg','ml-dsa-87',b64(2592)],
 ['origin','derived'],['seed_strength','256'],['v','nip-pqc/v1'],['pop','ml-dsa-87',b64(4627)]
]);
function maxText(pq) {
 let lo=1,hi=65000;
 while(lo<hi) {const m=Math.ceil((lo+hi)/2);if(dm(m,pq).legacyOuterFits)lo=m;else hi=m-1;}
 return lo;
}
assert.equal(hybrid(1).length,2192);
assert.equal(classical(1).length,132);
assert.equal(b64(4628).length,6172);
console.log(JSON.stringify({model:'ASCII text; one recipient p tag; fixed 10-digit timestamps; exact-length mock ciphertext/signatures; uncompressed client EVENT JSON; no network, keys or publication',rows,public_event:{classical:wire(base),hybrid:wire(signed),extra:wire(signed)-wire(base),proof_base64:6172},attestation_wire:wire(attestation),old_65535_outer_limit_max_text:{classical:maxText(false),hybrid:maxText(true)}},null,2));
