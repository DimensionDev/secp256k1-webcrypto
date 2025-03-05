import { type Name, usageToFlag, createKeyMaterial, type KeyMaterial, KeyUsages, usageFromFlag } from '../key.js'
import __ from 'elliptic'
import { Convert } from 'pvtsutils'
import { concat, hex2buffer } from '../helper.js'

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
        pub: createKeyMaterial(key, 'public', name, usage, extractable),
        priv: createKeyMaterial(key, 'private', name, usage, extractable),
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
    if (usage & KeyUsages.sign) if (!key_ops.includes('sign')) isValidKeyUsage = false
    if (usage & KeyUsages.verify) if (!key_ops.includes('verify')) isValidKeyUsage = false

    if (!isValidKeyUsage)
        throw new DOMException(
            'The JWK "key_ops" member was inconsistent with that specified by the Web Crypto call. The JWK usage must be a superset of those requested',
            'DataError',
        )
    //#endregion

    // 4 is the point format.
    const point = concat([4], new Uint8Array(Convert.FromBase64Url(x)), new Uint8Array(Convert.FromBase64Url(y)))
    const priv = d ? Convert.FromBase64Url(d) : undefined

    let ecKey: __.ec.KeyPair
    if (priv) ecKey = k256.keyFromPrivate(new Uint8Array(priv))
    else ecKey = k256.keyFromPublic(point)

    return createKeyMaterial(ecKey, d ? 'private' : 'public', name, usage, extractable)
}
function exportK256JWK(key: KeyMaterial): JsonWebKey {
    if (!key.extractable) throw new DOMException('key is not extractable', 'InvalidAccessError')
    // ignore first '04'
    const hexPub = key.key.getPublic('hex').slice(2)
    const hexX = hexPub.slice(0, hexPub.length / 2)
    const hexY = hexPub.slice(hexPub.length / 2, hexPub.length)
    if (key.type === 'public') {
        // public

        const jwk: JsonWebKey = {
            crv: 'K-256',
            ext: true,
            x: Convert.ToBase64Url(hex2buffer(hexX)),
            y: Convert.ToBase64Url(hex2buffer(hexY)),
            key_ops: usageFromFlag(key),
            kty: 'EC',
        }
        return jwk
    } else {
        const jwk: JsonWebKey = {
            crv: 'K-256',
            ext: true,
            d: Convert.ToBase64Url(hex2buffer(key.key.getPrivate('hex'))),
            x: Convert.ToBase64Url(hex2buffer(hexX)),
            y: Convert.ToBase64Url(hex2buffer(hexY)),
            key_ops: usageFromFlag(key),
            kty: 'EC',
        }
        return jwk
    }
}
