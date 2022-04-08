import { createSubtle } from "./core.js";

export const subtleCrypto = createSubtle(crypto.subtle, DOMException)
export { ShimCryptoKey } from './core.js'
