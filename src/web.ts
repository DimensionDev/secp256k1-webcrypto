import { createCrypto } from './core.js'

export const [crypto, { Crypto, CryptoKey, SubtleCrypto }, polyfill] = createCrypto(
    globalThis.crypto,
    globalThis.CryptoKey,
    DOMException,
)
