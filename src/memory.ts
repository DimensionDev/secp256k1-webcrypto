import type { KeyMaterial } from './key.js'

const { WeakMap } = globalThis
const { set: WeakMapSet, has: WeakMapHas, get: WeakMapGet } = WeakMap.prototype
const { apply } = Reflect

/** @internal */
export function createMemory() {
    const shimKeys = new WeakMap<object, KeyMaterial>()
    function has(object: any) {
        return apply(WeakMapHas, shimKeys, [object])
    }
    function set(object: object, value: KeyMaterial) {
        return apply(WeakMapSet, shimKeys, [object, value])
    }
    function get(instance: unknown): KeyMaterial {
        if (!isCryptoKey(instance)) throw new TypeError('Illegal invocation')
        return apply(WeakMapGet, shimKeys, [instance])
    }
    function isCryptoKey(instance: unknown) {
        if (has(instance)) return true
        if (typeof CryptoKey === 'function') if (instance instanceof CryptoKey) return true
        return false
    }
    return { has, set, get, isCryptoKey }
}
