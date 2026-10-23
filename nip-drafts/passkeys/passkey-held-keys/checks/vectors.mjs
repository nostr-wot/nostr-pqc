// Independent fixture checker. Run: node checks/vectors.mjs
// Arithmetic here is for public test fixtures, not production signing.
import crypto from 'node:crypto'
import fs from 'node:fs'

const NIP = new URL('../vectors.json', import.meta.url)
const WORDLIST = new URL('./english.txt', import.meta.url)

const problems = []
let checks = 0
function check(ok, what) {
  checks++
  if (!ok) problems.push(what)
  return ok
}
const eq = (a, b, what) => check(a === b, `${what}: expected ${b}, got ${a}`)

const hex = (b) => Buffer.from(b).toString('hex')
const unhex = (s) => Buffer.from(s, 'hex')
const utf8 = (s) => Buffer.from(s, 'utf8')
const sha256 = (b) => crypto.createHash('sha256').update(b).digest()
const hmac = (alg, key, data) => crypto.createHmac(alg, key).update(data).digest()

// ---- RFC 5869 HKDF-SHA256 ----
function hkdf(ikm, salt, info, length = 32) {
  const prk = hmac('sha256', salt, ikm)
  let t = Buffer.alloc(0)
  let okm = Buffer.alloc(0)
  for (let i = 1; okm.length < length; i++) {
    t = hmac('sha256', prk, Buffer.concat([t, info, Buffer.from([i])]))
    okm = Buffer.concat([okm, t])
  }
  return okm.subarray(0, length)
}

// ---- secp256k1, affine coordinates over BigInt ----
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const G = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
]
const mod = (a, m = P) => ((a % m) + m) % m
function inv(a) {
  let [r0, r1, s0, s1] = [mod(a), P, 1n, 0n]
  while (r1) {
    const q = r0 / r1
    ;[r0, r1] = [r1, r0 - q * r1]
    ;[s0, s1] = [s1, s0 - q * s1]
  }
  return mod(s0)
}
function add(p, q) {
  if (!p) return q
  if (!q) return p
  if (p[0] === q[0] && mod(p[1] + q[1]) === 0n) return null
  const l =
    p[0] === q[0] ? mod(3n * p[0] * p[0] * inv(2n * p[1])) : mod((q[1] - p[1]) * inv(q[0] - p[0]))
  const x = mod(l * l - p[0] - q[0])
  return [x, mod(l * (p[0] - x) - p[1])]
}
const neg = (p) => (p ? [p[0], mod(-p[1])] : null)
function powmod(b, e) {
  let r = 1n
  for (b = mod(b); e > 0n; e >>= 1n) {
    if (e & 1n) r = mod(r * b)
    b = mod(b * b)
  }
  return r
}
function mul(k, base = G) {
  let r = null
  let a = base
  for (; k > 0n; k >>= 1n) {
    if (k & 1n) r = add(r, a)
    a = add(a, a)
  }
  return r
}
const big = (b) => BigInt('0x' + (hex(b) || '0'))
const be32 = (n) => unhex(n.toString(16).padStart(64, '0'))
function validScalar(b) {
  const k = big(b)
  return b.length === 32 && k > 0n && k < N
}
function point(secret) {
  if (!validScalar(secret)) throw new Error('scalar out of range')
  return mul(big(secret))
}
const xonly = (secret) => be32(point(secret)[0])
function compressed(secret) {
  const [x, y] = point(secret)
  return Buffer.concat([Buffer.from([y & 1n ? 3 : 2]), be32(x)])
}
// BIP-340: the even-y point for an x-only key, or null if there is none.
function liftX(xb) {
  const x = big(xb)
  if (xb.length !== 32 || x >= P) return null
  const c = mod(x * x * x + 7n)
  const y = powmod(c, (P + 1n) / 4n)
  if (mod(y * y) !== c) return null
  return [x, y & 1n ? P - y : y]
}
function taggedHash(tag, msg) {
  const t = sha256(utf8(tag))
  return sha256(Buffer.concat([t, t, msg]))
}
function schnorrSign(msg, secret, aux) {
  const d0 = big(secret)
  const pub = point(secret)
  const d = pub[1] & 1n ? N - d0 : d0
  const auxHash = taggedHash('BIP0340/aux', aux)
  const t = Buffer.from(be32(d).map((b, i) => b ^ auxHash[i]))
  const k0 = mod(big(taggedHash('BIP0340/nonce', Buffer.concat([t, be32(pub[0]), msg]))), N)
  if (k0 === 0n) throw new Error('nonce is zero')
  const R = mul(k0)
  const k = R[1] & 1n ? N - k0 : k0
  const e = mod(big(taggedHash('BIP0340/challenge', Buffer.concat([be32(R[0]), be32(pub[0]), msg]))), N)
  return Buffer.concat([be32(R[0]), be32(mod(k + e * d, N))])
}
function schnorrVerify(pub, msg, sig) {
  const Pt = liftX(pub)
  if (!Pt || sig.length !== 64) return false
  const r = big(sig.subarray(0, 32))
  const s = big(sig.subarray(32))
  if (r >= P || s >= N) return false
  const e = mod(big(taggedHash('BIP0340/challenge', Buffer.concat([sig.subarray(0, 32), pub, msg]))), N)
  const R = add(mul(s), neg(mul(e, Pt)))
  return R !== null && !(R[1] & 1n) && R[0] === r
}

// ---- BIP-39 (English) and BIP-32 private derivation ----
const wordlist = fs.readFileSync(WORDLIST, 'utf8').trim().split('\n')
if (wordlist.length !== 2048) throw new Error('word list is not 2048 words')
function mnemonic(entropy) {
  const bits = [...entropy].map((b) => b.toString(2).padStart(8, '0')).join('')
  const cs = [...sha256(entropy)]
    .map((b) => b.toString(2).padStart(8, '0'))
    .join('')
    .slice(0, (entropy.length * 8) / 32)
  return (bits + cs).match(/.{11}/g).map((g) => wordlist[parseInt(g, 2)]).join(' ')
}
const bip39Seed = (words, passphrase = '') =>
  crypto.pbkdf2Sync(utf8(words.normalize('NFKD')), utf8('mnemonic' + passphrase.normalize('NFKD')), 2048, 64, 'sha512')
function derivePath(seed, path) {
  const parts = path.split('/')
  if (parts[0] !== 'm') throw new Error('path must start with m')
  let i = hmac('sha512', utf8('Bitcoin seed'), seed)
  let key = i.subarray(0, 32)
  let chain = i.subarray(32)
  for (const part of parts.slice(1)) {
    const hard = part.endsWith("'")
    const index = Number(hard ? part.slice(0, -1) : part) + (hard ? 0x80000000 : 0)
    const ser = Buffer.alloc(4)
    ser.writeUInt32BE(index >>> 0)
    const data = hard ? Buffer.concat([Buffer.alloc(1), key, ser]) : Buffer.concat([compressed(key), ser])
    i = hmac('sha512', chain, data)
    const k = mod(big(i.subarray(0, 32)) + big(key), N)
    if (big(i.subarray(0, 32)) >= N || k === 0n) throw new Error('invalid child')
    key = be32(k)
    chain = i.subarray(32)
  }
  return key
}

// Self-test against NIP-06's published vector before trusting the code above.
{
  const words = 'leader monkey parrot ring guide accident before fence cannon height naive bean'
  const k = derivePath(bip39Seed(words), "m/44'/1237'/0'/0/0")
  eq(hex(k), '7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a', 'self-test NIP-06 private key')
  eq(hex(xonly(k)), '17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917', 'self-test NIP-06 public key')
}

// ---- the NIP's rules ----
const MAGIC = '4e504b01'
function classify(h) {
  if (h === null) return { mode: 'unknown' }
  const b = unhex(h)
  const s = hex(b)
  if (b.length === 22 && s.startsWith('4e504b0101')) return { mode: 'derived', parameter_set: b[5] }
  if (b.length === 37 && s.startsWith('4e504b0102')) return { mode: 'stored', author: hex(b.subarray(5)) }
  if (b.length === 32) return { mode: 'stored', author: s, legacy: 'raw-pubkey', confirm_record: true }
  if (b.length === 33 && b[0] === 0x03) return { mode: 'stored', legacy: 'key-in-handle' }
  if (s.startsWith('4e504b')) return { mode: 'unsupported' }
  return { mode: 'unknown' }
}

function aadFor(type, rpId, author, cred) {
  const rp = utf8(rpId)
  if (rp.length > 255 || author.length !== 32 || cred.length > 0xffff) throw new Error('bad aad input')
  const len = Buffer.alloc(2)
  len.writeUInt16BE(cred.length)
  return Buffer.concat([unhex(MAGIC), Buffer.from([type, rp.length]), rp, author, len, cred])
}
const storeKey = (prf, salt, label) => hkdf(prf, salt, utf8(label))

function seal(ctx, label, type, plaintext) {
  const key = storeKey(unhex(ctx.prf_output), unhex(ctx.hkdf_salt), label)
  const aad = aadFor(type, ctx.rp_id, unhex(ctx.author), unhex(ctx.credential_id))
  const c = crypto.createCipheriv('aes-256-gcm', key, unhex(ctx.iv))
  c.setAAD(aad)
  const ct = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()])
  return { key, aad, record: Buffer.concat([unhex(MAGIC), Buffer.from([type]), unhex(ctx.iv), unhex(ctx.hkdf_salt), ct]) }
}

// Opens a record the way a reader does: type from offset 4, nothing guessed.
function open(record, ctx, label, types) {
  if (record.length < 5 + 12 + 32 + 16 || hex(record.subarray(0, 4)) !== MAGIC) throw new Error('not a record')
  const type = record[4]
  if (!types.includes(type)) throw new Error('unknown type')
  const iv = record.subarray(5, 17)
  const salt = record.subarray(17, 49)
  const body = record.subarray(49)
  const key = storeKey(unhex(ctx.prf_output), salt, label)
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv)
  d.setAAD(aadFor(type, ctx.rp_id, unhex(ctx.author), unhex(ctx.credential_id)))
  d.setAuthTag(body.subarray(body.length - 16))
  const plaintext = Buffer.concat([d.update(body.subarray(0, body.length - 16)), d.final()])
  if (plaintext.length > 65536) throw new Error('plaintext too long')
  return { type, plaintext }
}

// RFC 8259 JSON, strictly: a repeated member name in any object is an error.
// Returns the value and the source text of the top-level updated_at number.
function parseJson(src) {
  let i = 0
  let updatedAt
  const fail = (m) => {
    throw new Error(`JSON: ${m} at ${i}`)
  }
  const ws = () => {
    while (i < src.length && ' \t\n\r'.includes(src[i])) i++
  }
  const ESC = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }
  function str() {
    if (src[i++] !== '"') fail('expected a string')
    let out = ''
    for (;;) {
      if (i >= src.length) fail('unterminated string')
      const c = src[i++]
      if (c === '"') return out
      if (c.charCodeAt(0) < 0x20) fail('control character in a string')
      if (c !== '\\') {
        out += c
        continue
      }
      const e = src[i++]
      if (e in ESC) out += ESC[e]
      else if (e === 'u' && /^[0-9a-fA-F]{4}$/.test(src.slice(i, i + 4))) {
        out += String.fromCharCode(parseInt(src.slice(i, i + 4), 16))
        i += 4
      } else fail('bad escape')
    }
  }
  const NUM = /-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y
  function value(depth, name) {
    ws()
    const c = src[i]
    if (c === '{' || c === '[') {
      i++
      const obj = c === '{'
      const out = obj ? {} : []
      const seen = new Set()
      ws()
      if (src[i] === (obj ? '}' : ']')) {
        i++
        return out
      }
      for (;;) {
        if (obj) {
          ws()
          const k = str()
          if (seen.has(k)) fail(`member "${k}" repeated`)
          seen.add(k)
          ws()
          if (src[i++] !== ':') fail('expected :')
          Object.defineProperty(out, k, { value: value(depth + 1, k), enumerable: true, writable: true, configurable: true })
        } else out.push(value(depth + 1))
        ws()
        const sep = src[i++]
        if (sep === ',') continue
        if (sep === (obj ? '}' : ']')) return out
        fail('expected , or a closing bracket')
      }
    }
    if (c === '"') return str()
    for (const [lit, v] of [['true', true], ['false', false], ['null', null]]) {
      if (src.startsWith(lit, i)) {
        i += lit.length
        return v
      }
    }
    NUM.lastIndex = i
    const m = NUM.exec(src)
    if (!m) fail('unexpected character')
    i += m[0].length
    if (depth === 1 && name === 'updated_at') updatedAt = m[0]
    return Number(m[0])
  }
  const v = value(0)
  ws()
  if (i !== src.length) fail('trailing data')
  return { v, updatedAt }
}

// What a reader imports from a vault plaintext, per the vault rules: bad
// bytes, bad JSON, a wrong top-level type or an invalid seed make the whole
// vault invalid; an account entry with a problem of its own is skipped, like
// an unknown kind.
const isObject = (x) => x !== null && typeof x === 'object' && !Array.isArray(x)
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k)
// m/44'/1237'/ then one or more levels, decimal below 2^31, no leading zeros,
// ' for hardened, at most 255 levels in all (the BIP-32 depth limit).
const PREFIX = "m/44'/1237'/"
function validPath(p) {
  if (typeof p !== 'string' || !p.startsWith(PREFIX)) return false
  const levels = p.slice(PREFIX.length).split('/')
  return levels.length + 2 <= 255 && levels.every((l) => /^(0|[1-9][0-9]*)'?$/.test(l) && Number(l.replace("'", '')) < 0x80000000)
}
function readVault(bytes) {
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new Error('byte order mark')
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)
  const { v, updatedAt } = parseJson(text)
  if (!isObject(v)) throw new Error('vault is not an object')
  if (has(v, 'updated_at')) {
    if (typeof v.updated_at !== 'number' || !/^(0|[1-9][0-9]*)$/.test(updatedAt) || BigInt(updatedAt) > 2n ** 53n - 1n) {
      throw new Error('bad updated_at')
    }
  }
  if (has(v, 'ext') && !isObject(v.ext)) throw new Error('bad ext')
  if (!has(v, 'accounts') || !Array.isArray(v.accounts) || v.accounts.length === 0) throw new Error('vault without accounts')
  let seed = null
  let words = null
  if (has(v, 'seed')) {
    if (!isObject(v.seed)) throw new Error('bad seed')
    const e = v.seed.entropy
    if (typeof e !== 'string' || !/^[0-9a-f]*$/.test(e) || ![32, 40, 48, 56, 64].includes(e.length)) throw new Error('bad entropy')
    if (has(v.seed, 'passphrase') && typeof v.seed.passphrase !== 'string') throw new Error('bad passphrase')
    words = mnemonic(unhex(e))
    seed = bip39Seed(words, v.seed.passphrase ?? '')
  }
  const accounts = []
  const skipped = []
  v.accounts.forEach((a, index) => {
    const shaped =
      isObject(a) &&
      typeof a.kind === 'string' &&
      (!has(a, 'label') || typeof a.label === 'string') &&
      (!has(a, 'default') || typeof a.default === 'boolean')
    let secret = null
    if (shaped && a.kind === 'derived' && seed && validPath(a.path)) {
      try {
        secret = derivePath(seed, a.path)
      } catch {
        secret = null // BIP-32 gave an invalid key: skipped, never the next index
      }
    } else if (shaped && a.kind === 'key' && typeof a.secret === 'string' && /^[0-9a-f]{64}$/.test(a.secret) && validScalar(unhex(a.secret))) {
      secret = unhex(a.secret)
    }
    if (!secret) {
      skipped.push(index) // unknown kind, or a problem of its own
      return
    }
    const acc = { index }
    if (a.kind === 'derived') Object.assign(acc, { path: a.path, secret_key: hex(secret) })
    accounts.push({ ...acc, public_key: hex(xonly(secret)), default: a.default === true })
  })
  // The first usable account marked default, else the first usable account.
  const marked = accounts.find((a) => a.default)
  const default_index = marked ? marked.index : accounts.length ? accounts[0].index : null
  return { v, words, accounts, skipped, default_index }
}

function authorOk(type, plaintext, author) {
  if (type === 1) return plaintext.length === 32 && hex(xonly(plaintext)) === author
  if (type === 3) return readVault(plaintext).accounts.some((a) => a.public_key === author)
  return false
}

const b64urlDecode = (s) => Buffer.from(s.replace(/=+$/, ''), 'base64url')
const b64urlUnpadded = (b) => Buffer.from(b).toString('base64url').replace(/=+$/, '')
const b64urlPadded = (b) => {
  const u = b64urlUnpadded(b)
  return u + '='.repeat((4 - (u.length % 4)) % 4)
}

// Verify the exact external fixture bytes before recomputation.
const block = fs.readFileSync(NIP, 'utf8')
const stated = fs.readFileSync(new URL('../vectors.sha256', import.meta.url), 'utf8').split(/\s+/)[0]
eq(hex(sha256(utf8(block))), stated, 'SHA-256 of vectors.json')
const V = JSON.parse(block)

// ---- 2. handles ----
for (const h of V.handles) {
  const got = classify(h.handle)
  check(JSON.stringify(got) === JSON.stringify(h.expect), `handle "${h.description}": got ${JSON.stringify(got)}`)
}
for (const h of V.handles.filter((x) => x.description.includes('not a valid x-coordinate'))) {
  check(liftX(unhex(h.handle)) === null, `handle "${h.description}" is a valid x-coordinate`)
}
check(V.handles.some((x) => x.description.includes('not a valid x-coordinate')), 'no handle vector for an invalid x-coordinate')
for (const h of V.handles.filter((x) => x.handle !== null && x.handle.startsWith('4e504b01'))) {
  // No tagged handle of version 01 has length 32 (rule 3 would take it).
  if (unhex(h.handle).length === 32) check(h.expect.legacy === 'raw-pubkey', `handle "${h.description}" length 32`)
}

// ---- 3. derived parameter sets ----
for (const d of V.derived_parameter_sets) {
  const prfInput = sha256(utf8(d.salt_label))
  eq(hex(prfInput), d.prf_input, `derived ${d.parameter_set} prf_input`)
  const secret = hkdf(unhex(d.prf_output), prfInput, utf8(d.info_label))
  check(validScalar(secret), `derived ${d.parameter_set} scalar in range`)
  eq(hex(secret), d.secret_key, `derived ${d.parameter_set} secret_key`)
  eq(hex(xonly(secret)), d.public_key, `derived ${d.parameter_set} public_key`)
}
eq(V.derived_parameter_sets.find((d) => d.parameter_set === 1)?.salt_label, 'nostr-passkey:derive:v1', 'set 01 salt_label')
eq(V.derived_parameter_sets.find((d) => d.parameter_set === 2)?.info_label, 'lawallet-nsec-v1', 'set 02 info_label')

// ---- 4. stored records ----
const S = V.stored
eq(S.prf_label, 'nostr-passkey:store:v1', 'stored prf_label')
eq(hex(sha256(utf8(S.prf_label))), S.prf_input, 'stored prf_input')
eq(JSON.stringify(S.payload_types), JSON.stringify({ key: 1, vault: 3 }), 'payload types')
const TYPES = Object.values(S.payload_types)

S.records.forEach((r, i) => {
  const what = `record ${i} (${r.description.split(':')[0]})`
  if (r.prf_input) eq(r.prf_input, S.prf_input, `${what} prf_input`)
  const plaintext = unhex(r.plaintext)
  const sealed = seal(r, S.prf_label, r.payload_type, plaintext)
  if (r.aes_key) eq(hex(sealed.key), r.aes_key, `${what} aes_key`)
  if (r.aad) eq(hex(sealed.aad), r.aad, `${what} aad`)
  eq(hex(sealed.record), r.record, `${what} record`)
  eq(unhex(r.record).length, r.record_length, `${what} record_length`)
  if (r.record_base64) eq(unhex(r.record).toString('base64'), r.record_base64, `${what} record_base64`)
  let opened
  try {
    opened = open(unhex(r.record), r, S.prf_label, TYPES)
  } catch (e) {
    check(false, `${what} does not open: ${e.message}`)
    return
  }
  eq(opened.type, r.payload_type, `${what} type byte`)
  eq(hex(opened.plaintext), r.plaintext, `${what} decrypted plaintext`)
  check(authorOk(opened.type, opened.plaintext, r.author), `${what} author check`)
  if (r.payload_type === 3) {
    const vault = readVault(opened.plaintext)
    eq(JSON.stringify(vault.v), JSON.stringify(r.payload), `${what} payload object`)
    eq(hex(utf8(JSON.stringify(r.payload))), r.plaintext, `${what} plaintext is compact JSON`)
    eq(typeof vault.v.updated_at, 'number', `${what} updated_at`)
    eq(vault.words, r.expect.mnemonic, `${what} mnemonic`)
    const strip = (a) => {
      const o = { ...a }
      if (!o.default) delete o.default
      return o
    }
    eq(JSON.stringify(vault.accounts.map(strip)), JSON.stringify(r.expect.accounts), `${what} accounts`)
    eq(JSON.stringify(vault.skipped), JSON.stringify(r.expect.skipped), `${what} skipped accounts`)
    eq(vault.default_index, r.expect.default_index, `${what} default account`)
    check(Object.keys(vault.v.ext ?? {}).length > 0, `${what} carries ext data`)
    check(vault.skipped.some((i) => ['key', 'derived'].includes(vault.v.accounts[i].kind)), `${what} has an unusable account of a known kind`)
    check(vault.skipped.some((i) => vault.v.accounts[i].default === true), `${what} has a default on an ignored account`)
    check(vault.v.accounts.some((a) => a.path === "m/44'/1237'/0'/0/3"), `${what} has m/44'/1237'/0'/0/3`)
    check(vault.v.seed?.passphrase?.length > 0, `${what} has a passphrase`)
  }
})

// ---- 5. records that must fail ----
const INPUTS = ['record', 'prf_output', 'rp_id', 'author', 'credential_id']
for (const bad of S.invalid) {
  const base = S.records[bad.base]
  const ctx = { ...base, ...bad }
  const changed = INPUTS.filter((k) => bad[k] !== undefined && bad[k] !== base[k])
  check(changed.length === 1, `invalid "${bad.description}" changes ${changed.length} inputs`)
  eq(bad.expect, 'fail', `invalid "${bad.description}" expect`)
  let opened = false
  try {
    const o = open(unhex(ctx.record), ctx, S.prf_label, TYPES)
    opened = authorOk(o.type, o.plaintext, ctx.author)
  } catch {
    opened = false
  }
  check(!opened, `invalid "${bad.description}" opened`)
}
{
  const want = ['type', 'rp_id', 'author', 'credential_id']
  for (const w of want) check(S.invalid.some((x) => x.description.includes(w)), `no invalid vector for ${w}`)
}

// ---- 6. author not in vault ----
{
  const r = S.author_not_in_vault
  const sealed = seal(r, S.prf_label, r.payload_type, unhex(r.plaintext))
  eq(hex(sealed.record), r.record, 'author_not_in_vault record')
  try {
    const o = open(unhex(r.record), r, S.prf_label, TYPES)
    eq(hex(o.plaintext), r.plaintext, 'author_not_in_vault plaintext')
    check(!authorOk(o.type, o.plaintext, r.author), 'author_not_in_vault passes the author check')
  } catch (e) {
    check(false, `author_not_in_vault must open before failing the author check: ${e.message}`)
  }
  eq(r.expect, 'fail', 'author_not_in_vault expect')
}

// ---- 6b. vault plaintexts: parsing only ----
{
  const T = S.vault_plaintexts
  for (const t of T) {
    check((t.text === undefined) !== (t.hex === undefined), `vault plaintext "${t.description}" has one of text and hex`)
    const bytes = t.hex !== undefined ? unhex(t.hex) : utf8(t.text)
    let got
    try {
      const r = readVault(bytes)
      got = { usable: r.accounts.map((a) => a.index), skipped: r.skipped, default_index: r.default_index }
    } catch {
      got = 'invalid'
    }
    check(JSON.stringify(got) === JSON.stringify(t.expect), `vault plaintext "${t.description}": got ${JSON.stringify(got)}`)
  }
  const want = ['byte order mark', 'invalid UTF-8', 'repeated', 'fraction', 'exponent', '2^53', 'without entropy', 'passphrase not a string', 'accounts missing', 'without seed', 'first usable', 'depth', 'h marker']
  for (const w of want) check(T.some((t) => t.description.includes(w)), `no vault plaintext vector for "${w}"`)
}

// ---- 7. relay event and filter ----
{
  const r = S.records[0]
  const cred = unhex(r.credential_id)
  const { event, filter } = V.relay
  eq(event.kind, 31778, 'event kind')
  eq(event.pubkey, r.author, 'event pubkey')
  const tag = (n) => event.tags.find((t) => t[0] === n)?.[1]
  eq(tag('d'), `${b64urlUnpadded(cred)}:key`, 'event d tag')
  check(!event.tags.some((t) => t[0] === 'v'), 'event has no v tag')
  eq(tag('rp'), r.rp_id, 'event rp tag')
  check(!event.tags.some((t) => t[0] === 'credential'), 'event has no credential tag')
  eq(event.content, unhex(r.record).toString('base64'), 'event content')
  check(/^[A-Za-z0-9+/]*={0,2}$/.test(event.content) && event.content.length % 4 === 0, 'event content is padded base64')
  check(/^[A-Za-z0-9_-]+:(key|vault)$/.test(tag('d')), 'event d is unpadded base64url and a type name, nothing else')
  const o = open(Buffer.from(event.content, 'base64'), r, S.prf_label, TYPES)
  check(authorOk(o.type, o.plaintext, event.pubkey), 'event record opens for its pubkey')
  eq(JSON.stringify(filter.kinds), '[31778]', 'filter kinds')
  eq(JSON.stringify(filter.authors), JSON.stringify([r.author]), 'filter authors')
  // npk1 d values use the unpadded credential ID only.
  const want = [':key', ':vault'].map((t) => b64urlUnpadded(cred) + t)
  eq(JSON.stringify([...filter['#d']].sort()), JSON.stringify(want.sort()), 'filter #d values')
  check(filter['#d'].every((d) => !d.includes('=')), 'filter #d values are unpadded')
  for (const d of filter['#d']) {
    const c = d.slice(0, d.indexOf(':'))
    eq(hex(b64urlDecode(c)), r.credential_id, `filter "${d}" decodes to the credential`)
  }
  check(Object.keys(filter).every((k) => k === 'kinds' || k === 'authors' || /^#[a-zA-Z]$/.test(k)), 'filter uses single-letter tags only')
}

// ---- 7b. the signed relay event ----
{
  const se = V.relay.signed_event
  const e = se.event
  for (const k of ['pubkey', 'created_at', 'kind', 'tags', 'content']) {
    eq(JSON.stringify(e[k]), JSON.stringify(V.relay.event[k]), `signed event ${k} is relay.event's`)
  }
  const id = sha256(utf8(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])))
  eq(hex(id), e.id, 'signed event id (NIP-01)')
  eq(hex(xonly(unhex(se.secret_key))), e.pubkey, 'signed event secret_key gives pubkey')
  eq(se.secret_key, S.records[0].plaintext, 'signed event key is records[0] plaintext')
  check(schnorrVerify(unhex(e.pubkey), id, unhex(e.sig)), 'signed event signature verifies (BIP-340)')
  eq(hex(schnorrSign(id, unhex(se.secret_key), unhex(se.aux_rand))), e.sig, 'signed event sig reproduced from aux_rand')
  const bad = Buffer.from(unhex(e.sig))
  bad[63] ^= 1
  check(!schnorrVerify(unhex(e.pubkey), id, bad), 'a changed signature still verifies')
  // Eligible for records[0]'s passkey: v npk1, valid signature, pubkey = author, exact d.
  const tag = (n) => e.tags.find((t) => t[0] === n)?.[1]
  check(
    e.kind === 31778 && !e.tags.some((t) => t[0] === 'v') && e.pubkey === S.records[0].author && tag('d') === `${b64urlUnpadded(unhex(S.records[0].credential_id))}:key`,
    'signed event is eligible'
  )
}

// ---- 8. legacy PRF input and a keytr v=1 record ----
eq(hex(utf8(V.legacy_stored.prf_input_utf8)), V.legacy_stored.prf_input, 'legacy prf_input')
{
  const L = V.legacy_record
  eq(L.prf_input, V.legacy_stored.prf_input, 'legacy record prf_input')
  eq(L.hkdf_info, 'keytr nsec encryption v1', 'legacy record hkdf_info')
  const blob = unhex(L.blob)
  eq(blob.length, 93, 'legacy blob length')
  eq(L.blob_length, 93, 'legacy blob_length')
  eq(blob[0], 1, 'legacy blob version byte')
  const iv = blob.subarray(1, 13)
  const salt = blob.subarray(13, 45)
  eq(hex(iv), L.iv, 'legacy blob iv')
  eq(hex(salt), L.hkdf_salt, 'legacy blob salt')
  const key = hkdf(unhex(L.prf_output), salt, utf8(L.hkdf_info), 32)
  eq(hex(key), L.aes_key, 'legacy aes_key')
  const aad = Buffer.concat([utf8('keytr'), Buffer.from([1]), unhex(L.credential_id)])
  eq(hex(aad), L.aad, 'legacy aad')
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv)
    d.setAAD(aad)
    d.setAuthTag(blob.subarray(77))
    const secret = Buffer.concat([d.update(blob.subarray(45, 77)), d.final()])
    eq(hex(secret), L.secret_key, 'legacy decrypted secret')
    eq(hex(xonly(secret)), L.author, 'legacy author')
  } catch (err) {
    check(false, `legacy record does not decrypt: ${err.message}`)
  }
  eq(L.content, blob.toString('base64'), 'legacy content')
  eq(L.d, b64urlPadded(unhex(L.credential_id)), 'legacy d is padded base64url')
  eq(JSON.stringify(classify(L.author)), JSON.stringify({ mode: 'stored', author: L.author, legacy: 'raw-pubkey', confirm_record: true }), 'legacy author as a handle')
}

// ---- 8b. CTAP2 hmac-secret salt ----
{
  const ctapSalt = (input) => sha256(Buffer.concat([utf8('WebAuthn PRF'), Buffer.from([0]), input]))
  // Self-test on the WebAuthn specification's hmac-secret example (salt1).
  eq(hex(ctapSalt(unhex('576562417574686e20505246207465737420766563746f727302'))), '527413ebb48293772df30f031c5ac4650c7de14bf9498671ae163447b6a772b3', 'self-test WebAuthn hmac-secret salt1')
  eq(V.ctap2_salt.prf_input, S.prf_input, 'ctap2_salt prf_input is the stored one')
  eq(hex(ctapSalt(unhex(V.ctap2_salt.prf_input))), V.ctap2_salt.salt, 'ctap2_salt salt')
}

console.log(`${checks} checks on ${NIP}`)
if (problems.length) {
  console.log(`${problems.length} mismatches:`)
  for (const p of problems) console.log(' -', p)
  process.exit(1)
}
console.log('all vectors consistent')
