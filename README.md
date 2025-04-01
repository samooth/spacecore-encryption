# hypercore-encryption

Dyanmic Hypercore encryption provider

## Usage

```js
const HypercoreEncryption = require('hypercore-encryption')

async function get (id) {
  // get key info corresponding to id...

  return {
    version, // encryption scheme
    padding, // padding byte length
    key // block key
  }
}

const encryption = new HypercoreEncryption(blindingKey, get, {
  preopen: Promise.resolve(1) // optionally pass for initial id
})

const core = new Hypercore(storage, { encryption })
await core.ready()

await core.append('encrypt with key 1')

await encryption.load(99)

await core.append('encrypt with key 99')
```

## API

#### `const enc = new HypercoreEncryption(blindingKey, getBlockKey, { promise })`

Instantiate a new encryption provider. Optionally pass a `preopen` promise that resolves to a key id to be loaded initially.

Provide a hook with the signature:
```js
function getBlockKey (id) {
  return {
    version, // encryption scheme
    padding, // padding byte length
    key // block key
  }
}
```

Note: in compat mode, the key info returned at `0` should always be version `0`.

#### `await enc.ready()`

Wait for initial key to load if provided.

#### `enc.padding`

The number of padding bytes used by the current scheme.

#### `enc.seekable`

Boolean on whether the current scheme allows for seeks.

#### `enc.id`

The currently loaded key id.

#### `enc.version`

The version of the currently loaded scheme.

#### `await enc.load(id)`

Load the key under `id` and set to be the current encryption info.

#### `await enc.encrypt(index, block, fork)`

Encrypt a block in place.

#### `await enc.decrypt(index, block)`

Decrypt a block in place.

#### `HypercoreEncryption.isHypercoreEncryption(enc)`

Returns a boolean on whether `enc` is a valid encryption provider.

#### `const blockKey = HypercoreEncryption.getBlockKey(hypercoreKey, encryptionKey)`

Helper to generate namespaced block keys.

#### `const legacy = HypercoreEncryption.createLegacyProvider(blockKey)`

Create an encryption provider compatible with Hypercore's legacy encryption scheme.

## License

Apache-2.0
