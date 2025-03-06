const sodium = require('sodium-universal')
const c = require('compact-encoding')
const b4a = require('b4a')

const VERSION = 0

const nonce = b4a.alloc(sodium.crypto_stream_NONCEBYTES)

class BlockEncryption {
  constructor (padding, hooks = {}) {
    this.padding = padding
    this.seekable = this.padding !== 0

    this._get = hooks.get
    this.compat = false
  }

  async decrypt (index, block) {
    if (this.padding !== 8) throw new Error('Unsupported padding')

    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    const version = c.uint32.decode({ start: 0, end: 8, buffer: padding })
    if (version > VERSION) throw new Error('Unsupported version')

    const id = c.uint32.decode({ start: 4, end: 8, buffer: padding })

    const key = await this._get(id)
    if (!key) throw new Error('Decryption failed: unknown key')

    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

    nonce.set(padding, 8)

    return sodium.crypto_stream_xor(
      block,
      block,
      nonce,
      key
    )
  }

  async encrypt (id, index, block) {
    if (this.padding !== 8) throw new Error('Unsupported padding')

    const key = await this._get(id)
    if (!key) throw new Error('Encryption failed: unknown key')

    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    // encode padding
    c.uint32.encode({ start: 0, end: 8, buffer: padding }, VERSION)
    c.uint32.encode({ start: 4, end: 8, buffer: padding }, id)

    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

    // Zero out any previous padding.
    nonce.fill(0, 8, 8 + padding.byteLength)

    // TODO: don't blind for now: need a static blinding key a we don't know the encryptionId up front

    // sodium.crypto_stream_xor(
    //   padding,
    //   padding,
    //   nonce,
    //   this.blindingKey
    // )

    nonce.set(padding, 8)

    // The combination of a (blinded) fork ID and a block index is unique for a
    // given Hypercore and is therefore a valid nonce for encrypting the block.
    sodium.crypto_stream_xor(
      block,
      block,
      nonce,
      key
    )
  }
}

module.exports = BlockEncryption
