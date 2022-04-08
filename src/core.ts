import __ from 'elliptic'
const { ec } = __
import { Convert, combine } from 'pvtsutils'
import { createMemory } from './memory.js'
import { createKeyMaterial, KeyMaterial, KeyUsages } from './key.js'

type Name = 'ECDH' | 'ECDSA'
const k256 = new ec('secp256k1')
const { TypeError, Uint8Array, Promise } = globalThis
const { from } = Array
const { forEach, includes } = Array.prototype
const { apply } = Reflect
const { create, getPrototypeOf } = Object
const { get, has, isCryptoKey, set } = createMemory()

let DOMException: typeof globalThis.DOMException
export function createSubtle(nativeSubtle: SubtleCrypto, _DOMException: typeof globalThis.DOMException): SubtleCrypto {
    DOMException ??= _DOMException
    const SubtleCryptoPrototype: SubtleCrypto = getPrototypeOf(nativeSubtle)
    const { decrypt, deriveBits, deriveKey, digest, encrypt, exportKey } = SubtleCryptoPrototype
    const { generateKey, importKey, sign, unwrapKey, verify, wrapKey } = SubtleCryptoPrototype

    return {
        //#region Not Wrapping methods
        decrypt(algorithm, key, data) {
            return apply(decrypt, nativeSubtle, arguments)
        },
        digest(algorithm, data) {
            return apply(digest, nativeSubtle, arguments)
        },
        encrypt(algorithm, key, data) {
            return apply(encrypt, nativeSubtle, arguments)
        },
        unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
            return apply(unwrapKey, nativeSubtle, arguments)
        },
        wrapKey(format, key, wrappingKey, wrapAlgorithm) {
            if (has(key)) {
                throw new DOMException(
                    `Failed to execute 'wrapKey' on 'SubtleCrypto': Algorithm: K-256 key does not support wrapping.`,
                    'NotSupportedError',
                )
            }
            return apply(wrapKey, nativeSubtle, arguments)
        },
        //#endregion
        //#region Derive
        deriveBits(algorithm, baseKey, length) {
            return apply(deriveBits, nativeSubtle, arguments)
        },
        deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
            return apply(deriveKey, nativeSubtle, arguments)
        },
        //#endregion
        //#region Sign & Verify
        sign(algorithm, key, data) {
            return apply(sign, nativeSubtle, arguments)
        },
        verify(algorithm, key, signature, data) {
            return apply(verify, nativeSubtle, arguments)
        },
        //#endregion
        //#region Create, Import, Export
        generateKey(algorithm, extractable, keyUsages) {
            const k256Name = isK256Alg(algorithm)
            if (k256Name) return generateK256Pair(k256Name, extractable, keyUsages)
            return apply(generateKey, nativeSubtle, arguments)
        },
        importKey(format, keyData, algorithm, extractable, keyUsages) {
            const k256Name = isK256Alg(algorithm)
            if (k256Name) {
                return new Promise<any>((resolve) => {
                    if (format === 'pkcs8')
                        throw new DOMException('The key is not of the expected type', 'InvalidAccessError')
                    else if (format === 'spki')
                        throw new DOMException('spki export of K-256 keys is not supported', 'NotSupportedError')
                    else if (format === 'jwk') {
                        resolve(importK256JWK(k256Name, keyData as JsonWebKey, extractable, keyUsages))
                    } else if (format === 'raw') {
                        resolve(importK256Raw(k256Name, new Uint8Array(keyData as any), extractable, keyUsages))
                    } else throw new TypeError('Invalid keyFormat argument')
                })
            }
            return apply(importKey, nativeSubtle, arguments)
        },
        exportKey(format, key) {
            if (has(key)) {
                return new Promise<any>((resolve) => {
                    if (format === 'pkcs8')
                        throw new DOMException('The key is not of the expected type', 'InvalidAccessError')
                    else if (format === 'spki')
                        throw new DOMException('spki export of K-256 keys is not supported', 'NotSupportedError')
                    else if (format === 'jwk') resolve(exportK256JWK(get(key)))
                    else if (format === 'raw') resolve(exportK256Raw(get(key)))
                    else throw new TypeError('Invalid keyFormat argument')
                })
            } else return apply(exportKey, nativeSubtle, arguments)
        },
        //#endregion
    }
}

export class ShimCryptoKey implements CryptoKey {
    constructor() {
        throw new TypeError('Illegal constructor')
    }
    [Symbol.hasInstance](instance: unknown) {
        return isCryptoKey(instance)
    }
    get algorithm(): CryptoKey['algorithm'] {
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

function generateK256Pair(name: Name, extractable: boolean, usageList: readonly KeyUsage[]) {
    return new Promise<CryptoKeyPair>((resolve) => {
        const usage = usageToFlag(name, usageList)

        const publicKey: ShimCryptoKey = create(ShimCryptoKey.prototype)
        const privateKey: ShimCryptoKey = create(ShimCryptoKey.prototype)
        const key = k256.genKeyPair()

        set(publicKey, createKeyMaterial(key, 'public', name, usage, extractable))
        set(privateKey, createKeyMaterial(key, 'private', name, usage, extractable))

        resolve({ publicKey, privateKey })
    })
}
// !!! raw format can never store private key.
function importK256Raw(name: Name, buffer: ArrayBuffer, extractable: boolean, usage: readonly KeyUsage[]) {
    const pub = create(ShimCryptoKey.prototype)
    const key = k256.keyFromPublic(new Uint8Array(buffer))
    set(pub, createKeyMaterial(key, 'public', name, usageToFlag(name, usage), extractable))
    return pub
}
function exportK256Raw(key: KeyMaterial): ArrayBuffer {
    if (!key.extractable) throw new DOMException('key is not extractable', 'InvalidAccessError')
    return new Uint8Array(key.key.getPublic('array')).buffer
}
function importK256JWK(name: Name, jwk: JsonWebKey, extractable: boolean, usageList: readonly KeyUsage[]) {
    const usage = usageToFlag(name, usageList)

    //#region verify
    const { d, x, y, crv, kty } = jwk
    const key_ops = apply(from, Array, [jwk.key_ops])
    if (kty !== 'EC') throw new DOMException(`The required JWK member "kty" was missing`, 'DataError')
    if (crv !== 'K-256') throw new DOMException(`The required JWK member "crv" was missing`, 'DataError')
    if (!x) throw new DOMException(`The required JWK member "x" was missing`, 'DataError')
    if (!y) throw new DOMException(`The required JWK member "y" was missing`, 'DataError')

    let isValidKeyUsage = true
    if (usage & KeyUsages.deriveBits) if (!apply(includes, key_ops, ['deriveBits'])) isValidKeyUsage = false
    if (usage & KeyUsages.deriveKey) if (!apply(includes, key_ops, ['deriveKey'])) isValidKeyUsage = false
    if (usage & KeyUsages.sign) if (!apply(includes, key_ops, ['sign'])) isValidKeyUsage = false
    if (usage & KeyUsages.verify) if (!apply(includes, key_ops, ['verify'])) isValidKeyUsage = false
    if (!isValidKeyUsage)
        throw new DOMException(
            'The JWK "key_ops" member was inconsistent with that specified by the Web Crypto call. The JWK usage must be a superset of those requested',
            'DataError',
        )
    //#endregion
    const key = create(ShimCryptoKey.prototype)

    const point = combine(Convert.FromBase64Url(x), Convert.FromBase64Url(y))
    const priv = d ? Convert.FromBase64Url(d) : undefined

    let ecKey: __.ec.KeyPair
    if (priv) ecKey = k256.keyFromPrivate(new Uint8Array(priv))
    else ecKey = k256.keyFromPublic(new Uint8Array(point))

    set(key, createKeyMaterial(ecKey, d ? 'private' : 'public', name, usage, extractable))
    return key
}
function exportK256JWK(key: KeyMaterial): JsonWebKey {
    if (!key.extractable) throw new DOMException('key is not extractable', 'InvalidAccessError')
    throw new TypeError('Not implemented')
}
function usageToFlag(name: Name, usage: readonly KeyUsage[]) {
    let flag: KeyUsages = KeyUsages.None

    apply(forEach, usage, [
        (usage: KeyUsage) => {
            if (name === 'ECDH') {
                if (usage === 'deriveBits') return (flag |= KeyUsages.deriveBits)
                else if (usage === 'deriveKey') return (flag |= KeyUsages.deriveKey)
            } else if (name === 'ECDSA') {
                if (usage === 'sign') return (flag |= KeyUsages.sign)
                else if (usage === 'verify') return (flag |= KeyUsages.verify)
            }
            throw new DOMException('Cannot create a key using the specified key usages.', 'SyntaxError')
        },
    ])
    if (flag === KeyUsages.None) throw new DOMException('Usages cannot be empty when creating a key.', 'SyntaxError')
    if (name === 'ECDSA' && flag !== (KeyUsages.sign | KeyUsages.verify)) {
        throw new DOMException('Cannot create a key using the specified key usages.', 'SyntaxError')
    }
    return flag
}
function usageFromFlag(KeyMaterial: KeyMaterial): KeyUsage[] {
    const { usage, name, type } = KeyMaterial
    if (name === 'ECDH') {
        const result: KeyUsage[] = []
        if (type === 'private') return []
        if (usage & KeyUsages.deriveKey) result[result.length] = 'deriveKey'
        if (usage & KeyUsages.deriveBits) result[result.length] = 'deriveBits'
        return result
    } else {
        if (type === 'private') return ['sign']
        return ['verify']
    }
}
function isK256Alg(alg: unknown): Name | undefined {
    if (typeof alg !== 'object') return
    if (alg === null) return
    const { name, namedCurve } = alg as EcKeyAlgorithm
    if (namedCurve !== 'K-256') return
    if (name === 'ECDH' || name === 'ECDSA') return name
    return
}
