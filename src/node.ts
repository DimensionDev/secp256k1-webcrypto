import { webcrypto } from 'node:crypto'
import { createCrypto } from './core.js'

const Exception = typeof DOMException === 'function' ? DOMException : (TypeError as any)
export const [crypto, { Crypto, CryptoKey, SubtleCrypto }, polyfill] = createCrypto(
    webcrypto as any,
    (webcrypto as any).CryptoKey,
    Exception,
)
