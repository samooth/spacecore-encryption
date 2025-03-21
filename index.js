const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')
const ReadyResource = require('ready-resource')
const c = require('compact-encoding')
const b4a = require('b4a')

const [NS_BLOCK_KEY] = crypto.namespace('hypercore-encryption', 1)

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
    return LegacyProvider.encrypt(index, block, fork, this.blockKey, this.blindingKey)
  }

  decrypt (index, block) {
    return LegacyProvider.decrypt(index, block, this.blockKey)
  }

  static encrypt (index, block, fork, key, blindingKey) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    c.uint64.encode({ start: 0, end: 8, buffer: padding }, fork)
    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

    // Zero out any previous padding
    nonce.fill(0, 8)

    if (!blindingKey) blindingKey = crypto.hash(key)

    // Blind the fork ID, possibly risking reusing the nonce on a reorg of the
    // Hypercore. This is fine as the blinding is best-effort and the latest
    // fork ID shared on replication anyway
    encrypt(padding, nonce, blindingKey)

    nonce.set(padding, 8, 8 + padding.byteLength)

    // The combination of a (blinded) fork ID and a block index is unique for a
    // given Hypercore and is therefore a valid nonce for encrypting the block
    encrypt(block, nonce, key)
  }

  static decrypt (index, block, key) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    setNonce(index)

    nonce.set(padding, 8)
    nonce.fill(0, 8 + padding.byteLength)

    // Decrypt the block using the blinded fork ID
    decrypt(block, nonce, key)
  }
}

class BlockProvider {
  static version = TYPES.BLOCK
  static padding = 16

  static encrypt (index, block, fork, keyInfo, blindingKey, id) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    // Unkeyed hash of block as we blind it later
    sodium.crypto_generichash(padding, block)

    // Encode padding
    c.uint32.encode({ start: 0, end: 4, buffer: padding }, keyInfo.id)
    c.uint32.encode({ start: 4, end: 8, buffer: padding }, fork)

    setNonce(index)

    // Blind key id, fork id and block hash
    encrypt(padding, nonce, blindingKey)

    nonce.set(padding, 8)

    // The combination of index, key id, fork id and block hash is very likely
    // to be unique for a given Hypercore and therefore our nonce is suitable
    encrypt(block, nonce, keyInfo.key)
  }

  static decrypt (index, block, key, paddingBytes) {
    if (paddingBytes !== this.padding) throw new Error('Unsupported padding')

    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    setNonce(index)

    nonce.set(padding, 8)

    // Decrypt the block using the full nonce
    decrypt(block, nonce, key)
  }
}

class HypercoreEncryption extends ReadyResource {
  static KEYBYTES = sodium.crypto_stream_KEYBYTES

  constructor (blindingKey, opts = {}) {
    super()

    this.blindingKey = blindingKey

    this.getBlockKey = opts.get
    this.compat = opts.compat === true

    this.provider = null

    this.keys = new Map()

    this.current = opts.id !== undefined
      ? { id: opts.id, version: -1, key: null, padding: -1 }
      : null
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

  async _open () {
    if (this.current !== null) return this.load(this.current.id)
  }

  async _get (id) {
    if (this.keys.has(id)) return this.keys.get(id)

    const info = await this.getBlockKey(id)
    if (!info) throw new Error('Unrecognised encryption id')

    this.keys.set(id, info)

    return info
  }

  async load (id) {
    const info = await this._get(id)

    this.current = {
      id,
      version: info.version,
      key: info.key,
      padding: info.padding
    }
  }

  _parseId (index, block) {
    const id = b4a.alloc(4)
    id.set(block.subarray(0, 4))

    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)
    nonce.fill(0, 8)

    encrypt(id, nonce, this.blindingKey)

    return c.uint32.decode({ start: 0, end: 4, buffer: id })
  }

  async decrypt (index, block) {
    if (!this.opened) await this.ready()

    const id = this._parseId(index, block)
    const info = await this._get(id)

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

    if (this.current === null) {
      throw new Error('Encryption provider has not been loaded')
    }

    switch (this.current.version) {
      case LegacyProvider.version:
        return LegacyProvider.encrypt(index, block, fork, this.current.key, this.blindingKey)

      case BlockProvider.version: {
        return BlockProvider.encrypt(index, block, fork, this.current, this.blindingKey)
      }
    }
  }

  static isHypercoreEncryption (enc) {
    if (enc instanceof HypercoreEncryption) return true
    if (enc instanceof LegacyProvider) return true
    return false
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

function setNonce (index) {
  c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

  // Zero out any previous padding.
  nonce.fill(0, 8)
}

function encrypt (block, nonce, key) {
  sodium.crypto_stream_xor(
    block,
    block,
    nonce,
    key
  )
}

function decrypt (block, nonce, key) {
  return encrypt(block, nonce, key) // symmetric
}
