import { createSubtle } from './core.js'

export const [ShimCryptoKey, subtleCrypto] = createSubtle(crypto.subtle, CryptoKey, DOMException)
