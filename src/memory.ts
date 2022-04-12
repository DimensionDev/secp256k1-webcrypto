import { KeyMaterial, usageFromFlag } from './key.js'

/** @internal */
export function createMemory(nativeCryptoKey: typeof globalThis.CryptoKey | undefined) {
    const nativeCryptoKeyGetter = nativeCryptoKey
        ? Object.getOwnPropertyDescriptor(nativeCryptoKey.prototype, 'type')?.get
        : undefined

    const shimKeys = new WeakMap<object, KeyMaterial>()
    class CryptoKey implements globalThis.CryptoKey {
        constructor() {
            throw new TypeError('Illegal constructor')
        }
        [Symbol.hasInstance](instance: object) {
            if (shimKeys.has(instance)) return true
            if (isNativeCryptoKey(instance)) return true
            return false
        }
        get algorithm(): globalThis.CryptoKey['algorithm'] {
            const { name } = get(this)
            return { name, namedCurve: 'K-256' } as EcKeyAlgorithm
        }
        get extractable() {
            return get(this).extractable
        }
        get type(): KeyType {
            return get(this).type
        }
        get usages(): KeyUsage[] {
            return usageFromFlag(get(this))
        }
    }
    Object.defineProperty(CryptoKey, Symbol.toStringTag, { configurable: true, value: 'CryptoKey' })
    function has(object: any) {
        return shimKeys.has(object)
    }
    function get(instance: object): KeyMaterial {
        if (!shimKeys.has(instance)) throw new TypeError('Illegal invocation')
        return shimKeys.get(instance)!
    }
    function isNativeCryptoKey(instance: unknown) {
        if (!nativeCryptoKeyGetter) return false
        try {
            nativeCryptoKeyGetter.call(instance)
            return true
        } catch {
            return false
        }
    }
    function newKey(material: KeyMaterial): CryptoKey {
        const key = Object.create(CryptoKey.prototype)
        shimKeys.set(key, material)
        return key
    }
    return { has, get, CryptoKey, newKey }
}
