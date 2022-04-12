import { type Name, usageToFlag, createKeyMaterial, KeyMaterial, KeyUsages } from '../key.js'
import __ from 'elliptic'
import { combine, Convert } from 'pvtsutils'

const k256 = new __.ec('secp256k1')
/** @internal */
export function importK256(
    method: 'jwk' | 'raw',
    name: Name,
    data: JsonWebKey | BufferSource,
    extractable: boolean,
    usage: KeyUsages,
    DOMException: typeof globalThis.DOMException,
): KeyMaterial {
    if (method === 'jwk') return importK256JWK(name, data as JsonWebKey, extractable, usage, DOMException)
    return importK256Raw(name, new Uint8Array(data as ArrayBuffer), extractable, usage)
}
/** @internal */
export function exportK256(format: 'jwk' | 'raw', key: KeyMaterial) {
    if (format === 'jwk') return exportK256JWK(key)
    return exportK256Raw(key)
}
/** @internal */
export function generateK256Pair(
    name: Name,
    extractable: boolean,
    usageList: readonly KeyUsage[],
    DOMException: typeof globalThis.DOMException,
) {
    const usage = usageToFlag(name, usageList, DOMException)
    const key = k256.genKeyPair()

    return {
        priv: createKeyMaterial(key, 'public', name, usage, extractable),
        pub: createKeyMaterial(key, 'private', name, usage, extractable),
    }
}

// !!! raw format can never store private key.
function importK256Raw(name: Name, buffer: ArrayBuffer, extractable: boolean, usage: KeyUsages): KeyMaterial {
    const key = k256.keyFromPublic(new Uint8Array(buffer))
    return createKeyMaterial(key, 'public', name, usage, extractable)
}
function exportK256Raw(key: KeyMaterial): ArrayBuffer {
    if (!key.extractable) throw new DOMException('key is not extractable', 'InvalidAccessError')
    return new Uint8Array(key.key.getPublic('array')).buffer
}
function importK256JWK(
    name: Name,
    jwk: JsonWebKey,
    extractable: boolean,
    usage: KeyUsages,
    DOMException: typeof globalThis.DOMException,
): KeyMaterial {
    //#region verify
    const { d, x, y, crv, kty } = jwk
    const key_ops = Array.from(jwk.key_ops || [])
    if (kty !== 'EC') throw new DOMException(`The required JWK member "kty" was missing`, 'DataError')
    if (crv !== 'K-256') throw new DOMException(`The required JWK member "crv" was missing`, 'DataError')
    if (!x) throw new DOMException(`The required JWK member "x" was missing`, 'DataError')
    if (!y) throw new DOMException(`The required JWK member "y" was missing`, 'DataError')

    let isValidKeyUsage = true
    if (usage & KeyUsages.deriveBits) if (!key_ops.includes('deriveBits')) isValidKeyUsage = false
    if (usage & KeyUsages.deriveKey) if (!key_ops.includes('deriveKey')) isValidKeyUsage = false
    if (usage & KeyUsages.sign) if (!key_ops.includes('sign')) isValidKeyUsage = false
    if (usage & KeyUsages.verify) if (!key_ops.includes('verify')) isValidKeyUsage = false

    if (!isValidKeyUsage)
        throw new DOMException(
            'The JWK "key_ops" member was inconsistent with that specified by the Web Crypto call. The JWK usage must be a superset of those requested',
            'DataError',
        )
    //#endregion

    const point = combine(Convert.FromBase64Url(x), Convert.FromBase64Url(y))
    const priv = d ? Convert.FromBase64Url(d) : undefined

    let ecKey: __.ec.KeyPair
    if (priv) ecKey = k256.keyFromPrivate(new Uint8Array(priv))
    else ecKey = k256.keyFromPublic(new Uint8Array(point))

    return createKeyMaterial(ecKey, d ? 'private' : 'public', name, usage, extractable)
}
// TODO:
function exportK256JWK(key: KeyMaterial): JsonWebKey {
    if (!key.extractable) throw new DOMException('key is not extractable', 'InvalidAccessError')
    throw new TypeError('Not implemented')
}
