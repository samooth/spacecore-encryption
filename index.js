const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')
const ReadyResource = require('ready-resource')
const c = require('compact-encoding')
const b4a = require('b4a')

const [NS_BLOCK_KEY, NS_HASH_KEY] = crypto.namespace('hypercore-block-encryption', 2)

const TYPES = {
  LEGACY: 0,
  BLOCK: 1
}

const nonce = b4a.allocUnsafe(sodium.crypto_stream_NONCEBYTES)

class LegacyProvider {
  static version = TYPES.LEGACY
  static padding = 8

  constructor (blockKey) {
    this.blockKey = blockKey
    this.blindingKey = b4a.allocUnsafe(sodium.crypto_stream_KEYBYTES)

    this.seekable = true
    this.padding = LegacyProvider.padding

    sodium.crypto_generichash(this.blindingKey, this.blockKey)
  }

  ready () {
    // api compat
  }

  encrypt (index, block, fork) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    c.uint64.encode({ start: 0, end: 8, buffer: padding }, fork)
    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

    // Zero out any previous padding.
    nonce.fill(0, 8)

    // Blind the fork ID, possibly risking reusing the nonce on a reorg of the
    // Hypercore. This is fine as the blinding is best-effort and the latest
    // fork ID shared on replication anyway.
    sodium.crypto_stream_xor(
      padding,
      padding,
      nonce,
      this.blindingKey
    )

    nonce.set(padding, 8, 8 + padding.byteLength)

    // The combination of a (blinded) fork ID and a block index is unique for a
    // given Hypercore and is therefore a valid nonce for encrypting the block.
    sodium.crypto_stream_xor(
      block,
      block,
      nonce,
      this.blockKey
    )
  }

  decrypt (index, block) {
    return LegacyProvider.decrypt(index, block, this.blockKey)
  }

  static decrypt (index, block, key) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    setNonce(index)

    nonce.set(padding, 8)
    nonce.fill(0, 8 + padding.byteLength)

    // Decrypt the block using the blinded fork ID.
    sodium.crypto_stream_xor(
      block,
      block,
      nonce,
      key
    )
  }
}

class BlockProvider {
  static version = TYPES.BLOCK
  static padding = 16

  constructor (host, id, key) {
    this.isBlock = true

    this.host = host

    this.id = null
    this.key = null
    this.hashKey = null

    this.update(id, key)
  }

  update (id, key) {
    if (id === this.id) return // todo: maybe check key is equivalent

    this.id = id
    this.key = key

    if (key) this.hashKey = deriveHashKey(id, key)
  }

  // blind the key id and fork id, possibly risking reusing the nonce on a reorg.
  // chance is minimal since requires xsalsa20 collision of { keyId, forkId }
  _blind (padding) {
    sodium.crypto_stream_xor(
      padding,
      padding,
      nonce,
      this.host.blindingKey
    )
  }

  static decrypt (index, block, key, paddingBytes) {
    if (paddingBytes !== this.padding) throw new Error('Unsupported padding')

    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    setNonce(index)

    nonce.set(padding, 8)

    sodium.crypto_stream_xor(
      block,
      block,
      nonce,
      key
    )
  }

  encrypt (index, block, fork) {
    if (this.key === null) throw new Error('No encryption has been loaded')

    const padding = block.subarray(0, this.constructor.padding)
    block = block.subarray(this.constructor.padding)

    sodium.crypto_generichash(padding, block)

    // encode padding
    c.uint32.encode({ start: 0, end: 4, buffer: padding }, this.id)
    c.uint32.encode({ start: 4, end: 8, buffer: padding }, fork)

    setNonce(index)

    this._blind(padding) // blind

    nonce.set(padding, 8)

    // The combination of a index and a fork id and block hash is unique for a
    // given Hypercore and is therefore a valid nonce for encrypting the block.
    sodium.crypto_stream_xor(
      block,
      block,
      nonce,
      this.key
    )
  }
}

class HypercoreEncryption extends ReadyResource {
  static KEYBYTES = sodium.crypto_stream_KEYBYTES

  constructor (opts = {}) {
    super()

    this.getBlockKey = opts.get
    this.compat = opts.compat === true

    this.blindingKey = opts.blindingKey || null
    this.provider = null

    this.keyId = opts.id !== undefined ? opts.id : -1
  }

  get padding () {
    return this.compat ? LegacyProvider.padding : BlockProvider.padding
  }

  get seekable () {
    return this.padding !== 0
  }

  get encryptionKey () {
    return this.provider.blockKey
  }

  get bootstrapped () {
    return !!this.blindingKey
  }

  async _open () {
    if (this.keyId !== -1) return this.load(this.keyId)
  }

  async load (id) {
    const info = await this.getBlockKey(id, this.bootstrapped)
    if (!info) throw new Error('Unrecognised encryption id')

    const { version, key, blindingKey } = info

    if (!this.bootstrapped) {
      if (!blindingKey) throw new Error('Blinding key not provided')
      this.blindingKey = blindingKey
    }

    this.keyId = id

    switch (version) {
      case LegacyProvider.version: {
        this.provider = new LegacyProvider(key)
        break
      }

      case BlockProvider.version: {
        if (this.provider && this.provider instanceof BlockProvider) {
          return this.provider.update(id, key)
        }

        this.provider = new BlockProvider(this, id, key)
        break
      }
    }
  }

  _getId (index, block) {
    const id = b4a.alloc(4)
    id.set(block.subarray(0, 4))

    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)
    nonce.fill(0, 8)

    sodium.crypto_stream_xor(
      id,
      id,
      nonce,
      this.blindingKey
    )

    return c.uint32.decode({ start: 0, end: 4, buffer: id })
  }

  async decrypt (index, block) {
    if (!this.opened) await this.ready()

    const id = this._getId(index, block)

    const info = await this.getBlockKey(id)
    if (!info) throw new Error('Decryption failed: unknown key')

    const { version, key, padding } = info

    switch (version) {
      case LegacyProvider.version:
        return LegacyProvider.decrypt(index, block, key)

      case BlockProvider.version:
        return BlockProvider.decrypt(index, block, key, padding)

      default:
        throw new Error('Unrecognised version')
    }
  }

  async encrypt (index, block, fork) {
    if (!this.opened) await this.ready()
    return this.provider.encrypt(index, block, fork)
  }

  static getBlockKey (hypercoreKey, encryptionKey) {
    return getBlockKey(hypercoreKey, encryptionKey)
  }

  static createLegacyProvider (blockKey) {
    return new LegacyProvider(blockKey)
  }
}

module.exports = HypercoreEncryption

function getBlockKey (hypercoreKey, encryptionKey) {
  const key = b4a.allocUnsafe(sodium.crypto_stream_KEYBYTES)
  sodium.crypto_generichash_batch(key, [NS_BLOCK_KEY, hypercoreKey, encryptionKey])
  return key
}

function deriveHashKey (id, encryptionKey) {
  const idBuffer = c.encode(c.uint, id)
  const key = b4a.allocUnsafe(sodium.crypto_generichash_KEYBYTES)
  sodium.crypto_generichash_batch(key, [NS_HASH_KEY, idBuffer], encryptionKey)

  return key
}

function setNonce (index) {
  c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

  // Zero out any previous padding.
  nonce.fill(0, 8)
}
