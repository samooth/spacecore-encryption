# spacecore-encryption

Dyanmic Spacercore encryption provider

## Usage

```js
const SpacecoreEncryption = require('spacecore-encryption')

const encryption = new SpacecoreEncryption({
  blindingKey,
  getBlockKey (id, contexxt) {
    // get key info corresponding to id and context...

    return {
      version, // encryption scheme
      padding, // padding byte length
      key // block key
    }
  }
})

const core = new Spacecore(storage, { encryption })
await core.ready()

await core.append('encrypt with key 1')

await encryption.load(99)

await core.append('encrypt with key 99')
```

## API

#### `const enc = new SpacecoreEncryption({ blindingKey, getBlockKey, getBlindingKey })`

Instantiate a new encryption provider. Optionally pass a `preopen` promise that resolves to a key id to be loaded initially.

Provide a hooks with the signature:
```js
function getBlockKey (id, context) {
  // context provides information about the core, eg:
  //   context.key
  //   context.manifest

  // id id is passed as -1, the module expects the key to be updated

  return {
    version, // encryption scheme
    padding, // padding byte length
    key // block key
  }
}

function getBlockKey (context) {
  return blindingKey // 32 byte blinding key
}

```

#### `const padding = enc.padding(context)`

The number of padding bytes.

#### `enc.seekable`

Boolean on whether the current scheme allows for seeks.

#### `enc.version`

The version of the currently loaded scheme.

#### `await enc.load(id, context)`

Load the key under `id` and set to be the current encryption info.

#### `await enc.encrypt(index, block, fork)`

Encrypt a block in place.

#### `await enc.decrypt(index, block)`

Decrypt a block in place.

#### `const blockKey = SpacecoreEncryption.getBlockKey(spacecoreKey, encryptionKey)`

Helper to generate namespaced block keys.

## License

Apache-2.0
