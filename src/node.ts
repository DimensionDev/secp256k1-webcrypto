import { webcrypto } from 'node:crypto'
import { createSubtle } from './core.js'

const { subtle, CryptoKey } = webcrypto as any
const Exception = typeof DOMException === 'function' ? DOMException : (TypeError as any)
export const [ShimCryptoKey, subtleCrypto] = createSubtle(subtle, CryptoKey, Exception)
