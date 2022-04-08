import { webcrypto } from 'node:crypto'
import { createSubtle } from './core.js'

export const subtleCrypto = createSubtle(
    (webcrypto as any).subtle,
    typeof DOMException === 'function' ? DOMException : (TypeError as any),
)
export { ShimCryptoKey } from './core.js'
