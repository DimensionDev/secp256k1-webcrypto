import type { ec as EC } from 'elliptic'

const { Boolean } = globalThis
/** @internal */
export const enum KeyUsages {
    None = 0,
    deriveBits = 1 << 0,
    deriveKey = 1 << 1,
    sign = 1 << 2,
    verify = 1 << 3,
}
/** @internal */
export interface KeyMaterial {
    __proto__: null
    key: EC.KeyPair
    type: 'private' | 'public'
    name: Name
    usage: KeyUsages
    extractable: boolean
}
/** @internal */
export type Name = 'ECDH' | 'ECDSA'
/** @internal */
export function createKeyMaterial(
    key: EC.KeyPair,
    type: KeyMaterial['type'],
    name: KeyMaterial['name'],
    usage: KeyMaterial['usage'],
    extractable: boolean,
): KeyMaterial {
    return {
        __proto__: null,
        name,
        type,
        key,
        extractable: Boolean(extractable),
        usage,
    }
}
