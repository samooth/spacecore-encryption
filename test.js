const test = require('brittle')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')

const BlockEncryption = require('./')

test('basic', async t => {
  const blindingKey = b4a.alloc(32, b4a.from([0x12, 0x34]))

  const block = new BlockEncryption({
    async get (id) {
      await Promise.resolve()
      if (id === -1) return blindingKey
      return { key: b4a.alloc(32, id) }
    }
  })

  await block.ready()

  t.is(block.padding, 0)
  t.absent(block.seekable)

  await block.load(1)
  t.is(block.padding, 16)
  t.ok(block.seekable)

  const padding = block.padding

  const b0 = b4a.alloc(32, 0)
  const b1 = b4a.alloc(32, 1)
  const b2 = b4a.alloc(32, 2)

  const e0 = b4a.alloc(b0.byteLength + block.padding)
  const e1 = b4a.alloc(b1.byteLength + block.padding)
  const e2 = b4a.alloc(b2.byteLength + block.padding)

  e0.set(b0, padding)
  e1.set(b1, padding)
  e2.set(b2, padding)

  t.exception(() => block.encrypt(0, e0))

  await block.load(1)
  await block.encrypt(0, e0, 0)

  await block.load(2)
  await block.encrypt(1, e1, 1)

  await block.load(3)
  await block.encrypt(2, e2, 2)

  t.is(e0.byteLength, b0.byteLength + padding)
  t.is(e1.byteLength, b1.byteLength + padding)
  t.is(e2.byteLength, b2.byteLength + padding)

  await block.decrypt(0, e0)
  await block.decrypt(1, e1)
  await block.decrypt(2, e2)

  t.alike(e0.subarray(padding), b0)
  t.alike(e1.subarray(padding), b1)
  t.alike(e2.subarray(padding), b2)
})

test('legacy', async t => {
  const legacyOpts = {
    block: true,
    encryptionKey: b4a.alloc(32, 0)
  }

  const block = new BlockEncryption({
    legacy: true,
    get (id) {
      if (id === 0) return legacyOpts
    }
  })

  await block.ready()

  const b0 = b4a.alloc(32, 0)
  const b1 = b4a.alloc(32, 1)
  const b2 = b4a.alloc(32, 2)

  const e0 = b4a.alloc(40)
  const e1 = b4a.alloc(40)
  const e2 = b4a.alloc(40)

  e0.set(b0, 8)
  e1.set(b1, 8)
  e2.set(b2, 8)

  t.is(block.padding, 8)
  t.ok(block.seekable)

  block.encrypt(0, e0, 0)
  block.encrypt(1, e1, 1)
  block.encrypt(2, e2, 2)

  t.is(e0.byteLength, b0.byteLength + 8)
  t.is(e1.byteLength, b1.byteLength + 8)
  t.is(e2.byteLength, b2.byteLength + 8)

  block.decrypt(0, e0)
  block.decrypt(1, e1)
  block.decrypt(2, e2)

  t.alike(e0.subarray(8), b0)
  t.alike(e1.subarray(8), b1)
  t.alike(e2.subarray(8), b2)
})

test('encryption provider can decrypt legacy', async t => {
  const legacyOpts = {
    block: true,
    encryptionKey: b4a.alloc(32, 0)
  }

  const blindingKey = crypto.hash(legacyOpts.encryptionKey)

  const legacy = new BlockEncryption({
    legacy: true,
    get () { return legacyOpts }
  })

  const block = new BlockEncryption({
    id: 1,
    async get (id) {
      await Promise.resolve()
      if (id === -1) return blindingKey
      if (id === 0) return legacyOpts
      return { key: b4a.alloc(32, id) }
    }
  })

  await legacy.ready()

  await block.ready()

  const b0 = b4a.alloc(32, 0)
  const b1 = b4a.alloc(32, 1)
  const b2 = b4a.alloc(32, 2)
  const b3 = b4a.alloc(32, 3)

  const e0 = b4a.alloc(32 + legacy.padding)
  const e1 = b4a.alloc(32 + legacy.padding)
  const e2 = b4a.alloc(32 + legacy.padding)
  const e3 = b4a.alloc(32 + block.padding)

  // legacy scheme
  e0.set(b0, legacy.padding)
  e1.set(b1, legacy.padding)
  e2.set(b2, legacy.padding)

  legacy.encrypt(0, e0, 0) // fork has to be pegged to 0
  legacy.encrypt(1, e1, 0)
  legacy.encrypt(2, e2, 0)

  // updated scheme
  e3.set(b3, block.padding)

  block.encrypt(3, e3, 3)

  t.is(e0.byteLength, b0.byteLength + 8)
  t.is(e1.byteLength, b1.byteLength + 8)
  t.is(e2.byteLength, b2.byteLength + 8)

  await block.decrypt(0, e0)
  await block.decrypt(1, e1)
  await block.decrypt(2, e2)
  await block.decrypt(3, e3)

  t.alike(e0.subarray(legacy.padding), b0)
  t.alike(e1.subarray(legacy.padding), b1)
  t.alike(e2.subarray(legacy.padding), b2)
  t.alike(e3.subarray(block.padding), b3)
})
