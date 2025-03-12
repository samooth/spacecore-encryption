const test = require('brittle')
const b4a = require('b4a')

const BlockEncryption = require('./')

test('basic', async t => {
  const block = new BlockEncryption(8, {
    async get (id) {
      await Promise.resolve()
      return b4a.alloc(32, id)
    }
  })

  t.is(block.padding, 8)
  t.ok(block.seekable)

  const b0 = b4a.alloc(32, 0)
  const b1 = b4a.alloc(32, 1)
  const b2 = b4a.alloc(32, 2)

  const e0 = b4a.alloc(40)
  const e1 = b4a.alloc(40)
  const e2 = b4a.alloc(40)

  e0.set(b0, 8)
  e1.set(b1, 8)
  e2.set(b2, 8)

  t.exception(() => block.encrypt(0, e0))

  await block.reload(0)
  await block.encrypt(0, e0)

  await block.reload(1)
  await block.encrypt(1, e1)

  await block.reload(2)
  await block.encrypt(2, e2)

  t.is(e0.byteLength, b0.byteLength + 8)
  t.is(e1.byteLength, b1.byteLength + 8)
  t.is(e2.byteLength, b2.byteLength + 8)

  await block.decrypt(0, e0)
  await block.decrypt(1, e1)
  await block.decrypt(2, e2)

  t.alike(e0.subarray(8), b0)
  t.alike(e1.subarray(8), b1)
  t.alike(e2.subarray(8), b2)
})
