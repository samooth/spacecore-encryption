const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')
const ReadyResource = require('ready-resource')
const c = require('compact-encoding')
const b4a = require('b4a')

const [NS_BLOCK_KEY, NS_HASH_KEY] = crypto.namespace('hypercore-block-encryption', 2)

const LEGACY_KEY_ID = 0
const BYPASS_KEY_ID = 0xffffffff

const nonce = b4a.allocUnsafe(sodium.crypto_stream_NONCEBYTES)
const blindingNonce = b4a.allocUnsafe(sodium.crypto_stream_NONCEBYTES)

class LegacyProvider {
  static id = LEGACY_KEY_ID
  static padding = 8

  constructor (encryptionKey, blockKey) {
    this.encryptionKey = encryptionKey
    this.blockKey = blockKey
    this.blindingKey = b4a.allocUnsafe(sodium.crypto_stream_KEYBYTES)

    this.padding = LegacyProvider.padding

    sodium.crypto_generichash(this.blindingKey, this.blockKey)
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

    nonce.set(padding, 8)

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
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

    nonce.set(padding, 8)

    return LegacyProvider.decrypt(index, block, this.blockKey)
  }

  static decrypt (index, block, key) {
    // Decrypt the block using the blinded fork ID.
    sodium.crypto_stream_xor(
      block,
      block,
      nonce,
      key
    )
  }
}

class EncryptionProvider {
  constructor (host, id, key) {
    this.padding = 16
    this.isBlock = true

    this.host = host

    this.id = null
    this.key = null
    this.hashKey = null
    this.blindingKey = host.blindingKey

    this.update(id, key)
  }

  update (id, key) {
    this.id = id
    this.key = key

    if (key) this.hashKey = deriveHashKey(id, key)
  }

  _decodeKeyId (padding) {
    this._blind(padding) // unblind

    return c.uint32.decode({ start: 0, end: 4, buffer: padding })
  }

  _setNonce (index) {
    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)
    c.uint64.encode({ start: 0, end: 8, buffer: blindingNonce }, index)

    // Zero out any previous padding.
    nonce.fill(0, 8)
    blindingNonce.fill(0, 8)
  }

  // blind the key id and fork id, possibly risking reusing the nonce on a reorg.
  // chance is minimal since requires xsalsa20 collision of { keyId, forkId }
  _blind (padding) {
    sodium.crypto_stream_xor(
      padding,
      padding,
      blindingNonce,
      this.blindingKey
    )
  }

  // reset legacy state
  _resetLegacyPadding (padding) {
    nonce.fill(0, this.padding)
    this._blind(padding) // we wrote 8 bytes of the legacy block while unblinding
  }

  async decrypt (index, raw) {
    if (this.padding !== 16) throw new Error('Unsupported padding')

    const padding = raw.subarray(0, this.padding)
    const block = raw.subarray(this.padding)

    this._setNonce(index)

    nonce.set(padding, 8)

    const id = this._decodeKeyId(padding)

    const key = await this.host.getBlockKey(id)
    if (!key) throw new Error('Decryption failed: unknown key')

    // handle special cases
    switch (id) {
      case LegacyProvider.id: {
        this._resetLegacyPadding(padding)
        const block = raw.subarray(LegacyProvider.padding)

        return LegacyProvider.decrypt(index, block, key)
      }

      case BypassProvider.id:
        return block
    }

    return sodium.crypto_stream_xor(
      block,
      block,
      nonce,
      key
    )
  }

  encrypt (index, block, fork) {
    if (this.key === null) throw new Error('No encryption has been loaded')
    if (this.padding !== 16) throw new Error('Unsupported padding')

    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    sodium.crypto_generichash(padding, block)

    // encode padding
    c.uint32.encode({ start: 0, end: 4, buffer: padding }, this.id)
    c.uint32.encode({ start: 4, end: 8, buffer: padding }, fork)

    this._setNonce(index)
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

class BypassProvider extends EncryptionProvider {
  static id = BYPASS_KEY_ID

  constructor (key, host) {
    super(BypassProvider.id, key, host)
  }

  encrypt (index, block) {
    const padding = block.subarray(0, this.padding)
    block = block.subarray(this.padding)

    // encode padding
    c.uint32.encode({ start: 0, end: 4, buffer: padding }, this.id)
    this._blind(padding) // blind
  }
}

class HypercoreEncryption extends ReadyResource {
  static KEYBYTES = sodium.crypto_stream_KEYBYTES

  constructor (opts = {}) {
    super()

    this.getBlockKey = opts.get
    this.compat = false

    this.blindingKey = null
    this.provider = null

    this.keyId = opts.id !== undefined ? opts.id : null
  }

  get padding () {
    return this.provider ? this.provider.padding : 0
  }

  get seekable () {
    return this.padding !== 0
  }

  get encryptionKey () {
    return this.provider.blockKey
  }

  async _open () {
    if (this.keyId === LegacyProvider.id) {
      return this.load(LegacyProvider.id)
    }

    const legacyKey = await this.getBlockKey(LEGACY_KEY_ID)
    if (!legacyKey) throw new Error('Blinding key must be provided')

    this.blindingKey = b4a.allocUnsafe(sodium.crypto_stream_KEYBYTES)
    sodium.crypto_generichash(this.blindingKey, legacyKey)

    if (this.keyId !== null) return this.load(this.keyId)
  }

  async load (id) {
    const key = await this.getBlockKey(id)
    if (!key) throw new Error('Unrecognised encryption id')

    this.keyId = id

    switch (id) {
      case LegacyProvider.id: {
        this.provider = new LegacyProvider(key)
        break
      }

      case BypassProvider.id: {
        this.provider = new BypassProvider(this, key)
        break
      }

      default: {
        if (this.provider && this.provider instanceof EncryptionProvider) {
          return this.provider.update(id, key)
        }

        this.provider = new EncryptionProvider(this, id, key)
        break
      }
    }
  }

  async decrypt (index, block) {
    if (!this.opened) await this.ready()
    return this.provider.decrypt(index, block)
  }

  async encrypt (index, block, fork) {
    if (!this.opened) await this.ready()
    return this.provider.encrypt(index, block, fork)
  }

  static getBlockKey (hypercoreKey, encryptionKey) {
    return getBlockKey(hypercoreKey, encryptionKey)
  }

  static createLegacyProvider (encryptionKey, blockKey) {
    return new LegacyProvider(encryptionKey, blockKey)
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
