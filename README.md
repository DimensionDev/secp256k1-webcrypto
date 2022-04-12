# secp256k1-webcrypto

WebCrypto API with secp256k1 support.

This is a light version of <https://github.com/PeculiarVentures/webcrypto-liner/> that only contains secp256k1 support.

Thanks to `PeculiarVentures` for their webcrypto-liner!

## Requirement

- Node: Have [native WebCrypto](https://nodejs.org/api/webcrypto.html#web-crypto-api) support.
- Web: Have [native WebCrypro](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) support.

You can create your own instance by `@dimensiondev/secp256k1-webcrypto`

```js
import { createSubtle } from './core.js'
export const [ShimCryptoKey, subtleCrypto] = createSubtle(yourWebCryptoSubtle, CryptoKeyClass, DOMExceptionClass)
```

## Unsupported

- spki format import/export
