import type { ec as EC } from 'elliptic'

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
        extractable: !!extractable,
        usage,
    }
}
/** @internal */
export function usageToFlag(name: Name, usageList: readonly KeyUsage[], DOMException: typeof globalThis.DOMException) {
    let flag: KeyUsages = KeyUsages.None

    for (const usage of usageList) {
        if (name === 'ECDH') {
            if (usage === 'deriveBits') {
                flag |= KeyUsages.deriveBits
                continue
            } else if (usage === 'deriveKey') {
                flag |= KeyUsages.deriveKey
                continue
            }
        } else if (name === 'ECDSA') {
            if (usage === 'sign') {
                flag |= KeyUsages.sign
                continue
            } else if (usage === 'verify') {
                flag |= KeyUsages.verify
                continue
            }
        }
        throw new DOMException('Cannot create a key using the specified key usages.', 'SyntaxError')
    }
    if (flag === KeyUsages.None) {
        throw new DOMException('Usages cannot be empty when creating a key.', 'SyntaxError')
    }
    // if (name === 'ECDSA' && flag !== (KeyUsages.sign | KeyUsages.verify)) {
    //     throw new DOMException('Cannot create a key using the specified key usages.', 'SyntaxError')
    // }
    return flag
}
/** @internal */
export function usageFromFlag(KeyMaterial: KeyMaterial): KeyUsage[] {
    const { usage, name, type } = KeyMaterial
    if (name === 'ECDH') {
        const result: KeyUsage[] = []
        if (type === 'private') return []
        if (usage & KeyUsages.deriveKey) result.push('deriveKey')
        if (usage & KeyUsages.deriveBits) result.push('deriveBits')
        return result
    } else {
        if (type === 'private') return ['sign']
        return ['verify']
    }
}
