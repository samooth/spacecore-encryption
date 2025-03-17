const sodium = require('sodium-universal')
const ReadyResource = require('ready-resource')
const c = require('compact-encoding')
const b4a = require('b4a')

const {
  NS_LEGACY_ENCRYPTION,
  NS_HASH_KEY,
  LEGACY_KEY_ID,
  BLINDING_KEY_ID,
  BYPASS_KEY_ID
} = require('./lib/caps.js')

const nonce = b4a.alloc(sodium.crypto_stream_NONCEBYTES)
const blindingNonce = b4a.alloc(sodium.crypto_stream_NONCEBYTES)

class LegacyProvider {
  static id = LEGACY_KEY_ID
  static padding = 8

  constructor ({ encryptionKey, hypercoreKey, block = false, compat = true } = {}) {
    const subKeys = b4a.alloc(2 * sodium.crypto_stream_KEYBYTES)

    this.key = encryptionKey
    this.blockKey = block ? encryptionKey : subKeys.subarray(0, sodium.crypto_stream_KEYBYTES)
    this.blindingKey = subKeys.subarray(sodium.crypto_stream_KEYBYTES)

    this.isBlock = !!block
    this.padding = LegacyProvider.padding

    this.compat = compat

    if (!block) {
      if (compat) sodium.crypto_generichash_batch(this.blockKey, [encryptionKey], hypercoreKey)
      else sodium.crypto_generichash_batch(this.blockKey, [NS_LEGACY_ENCRYPTION, hypercoreKey, encryptionKey])
    }

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

    return c.uint32.deocde({ start: 0, end: 4, buffer: padding })
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

  // reset padding state
  _resetLegacy (padding) {
    nonce.fill(0, this.padding)
    this._blind(padding)
  }

  async decrypt (index, raw) {
    if (this.padding !== 16) throw new Error('Unsupported padding')

    const padding = raw.subarray(0, this.padding)
    const block = raw.subarray(this.padding)

    this._setNonce(index)

    nonce.set(padding, 8)

    const id = this._decodeKeyId(padding)

    const opts = await this.host._get(id)
    if (!opts) throw new Error('Decryption failed: unknown key')

    // handle special cases
    switch (id) {
      case LegacyProvider.id: {
        this._resetLegacy(padding)
        const block = raw.subarray(LegacyProvider.padding)

        return LegacyProvider.decrypt(index, block, opts.encryptionKey)
      }

      case BypassProvider.id:
        return block
    }

    return sodium.crypto_stream_xor(
      block,
      block,
      nonce,
      opts.key
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
    padding.fill(0, 4, padding.byteLength)
  }
}

class HypercoreEncryption extends ReadyResource {
  constructor (opts = {}) {
    super()

    this._get = opts.get
    this.legacy = opts.legacy === true || opts.id === 0
    this.compat = false

    this.blindingKey = null
    this.provider = null

    this._initialId = opts.id !== undefined ? opts.id : null
  }

  get padding () {
    return this.provider ? this.provider.padding : 0
  }

  get seekable () {
    return this.padding !== 0
  }

  async _open () {
    if (this.legacy) {
      return this.load(LegacyProvider.id)
    }

    const blindingKey = await this._get(BLINDING_KEY_ID)
    if (!blindingKey) throw new Error('Blinding key must be provided')

    this.blindingKey = blindingKey

    const id = this._initialId
    if (id !== null) {
      this._initialId = null
      return this.load(id)
    }
  }

  async load (id) {
    const opts = await this._get(id)
    if (!opts) throw new Error('Unrecognised encryption id')

    switch (id) {
      case LegacyProvider.id: {
        this.provider = new LegacyProvider(opts)
        break
      }

      case BypassProvider.id: {
        this.provider = new BypassProvider(this, opts.key)
        break
      }

      default: {
        if (this.provider && this.provider instanceof EncryptionProvider) {
          return this.provider.update(id, opts.key)
        }

        this.provider = new EncryptionProvider(this, id, opts.key)
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
}

module.exports = HypercoreEncryption

function deriveHashKey (id, encryptionKey) {
  const idBuffer = c.encode(c.uint, id)
  const key = b4a.alloc(sodium.crypto_generichash_KEYBYTES)
  sodium.crypto_generichash_batch(key, [NS_HASH_KEY, idBuffer], encryptionKey)

  return key
}
