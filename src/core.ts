import __ from 'elliptic'
import { createMemory } from './memory.js'
import { signK256, verifyK256 } from './ec/sign.js'
import { getHashAlg, isK256Alg } from './helper.js'
import { exportK256, generateK256Pair, importK256 } from './ec/key.js'
import { usageToFlag } from './key.js'
import { deriveBitsK256 } from './ec/derive.js'

export function createSubtle(
    nativeSubtle: SubtleCrypto,
    nativeCryptoKey: typeof globalThis.CryptoKey | undefined,
    DOMException: typeof globalThis.DOMException,
): readonly [typeof CryptoKey, SubtleCrypto] {
    const { get, has, ShimCryptoKey, newKey } = createMemory(nativeCryptoKey)

    const shimSubtleCrypto: SubtleCrypto = {
        //#region Not Wrapping methods
        decrypt(algorithm, key, data) {
            return nativeSubtle.decrypt(algorithm, key, data)
        },
        digest(algorithm, data) {
            return nativeSubtle.digest(algorithm, data)
        },
        encrypt(algorithm, key, data) {
            return nativeSubtle.encrypt(algorithm, key, data)
        },
        unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
            return nativeSubtle.unwrapKey(
                format,
                wrappedKey,
                unwrappingKey,
                unwrapAlgorithm,
                unwrappedKeyAlgorithm,
                extractable,
                keyUsages,
            )
        },
        async wrapKey(format, key, wrappingKey, wrapAlgorithm) {
            if (has(key)) {
                throw new DOMException(
                    `Failed to execute 'wrapKey' on 'SubtleCrypto': Algorithm: K-256 key does not support wrapping.`,
                    'NotSupportedError',
                )
            }
            return nativeSubtle.wrapKey(format, key, wrappingKey, wrapAlgorithm)
        },
        //#endregion
        //#region Derive
        async deriveBits(algorithm, baseKey, length) {
            if (isK256Alg(algorithm, 'ECDH')) {
                return deriveBitsK256(get((algorithm as EcdhKeyDeriveParams).public), get(baseKey), length)
            }

            return nativeSubtle.deriveBits(algorithm, baseKey, length)
        },
        async deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
            if (isK256Alg(algorithm, 'ECDH')) {
                const alg = algorithm as EcdhKeyDeriveParams
                const aes = derivedKeyType as AesDerivedKeyParams

                const bits = deriveBitsK256(get(alg.public), get(baseKey), aes.length)
                return nativeSubtle.importKey('raw', bits, derivedKeyType, extractable, keyUsages)
            }
            return nativeSubtle.deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages)
        },
        //#endregion
        //#region Sign & Verify
        async sign(algorithm, key, data) {
            if (isK256Alg(algorithm, 'ECDSA')) {
                if (!has(key)) {
                    throw new TypeError(
                        `Failed to execute 'sign' on 'SubtleCrypto': parameter 2 is not of type 'CryptoKey'.`,
                    )
                }
                const hash = getHashAlg(algorithm)
                if (!hash) {
                    throw new DOMException(
                        `Failed to execute 'sign' on 'SubtleCrypto': EcdsaParams: hash: Algorithm: Unrecognized name`,
                        'NotSupportedError',
                    )
                }
                const hashed = await nativeSubtle.digest(hash, data)
                return signK256(get(key), hashed)
            }
            return nativeSubtle.sign(algorithm, key, data)
        },
        async verify(algorithm, key, signature, data) {
            if (isK256Alg(algorithm, 'ECDSA')) {
                if (!has(key))
                    throw new TypeError(
                        `Failed to execute 'verify' on 'SubtleCrypto': parameter 2 is not of type 'CryptoKey'.`,
                    )

                const hash = getHashAlg(algorithm)
                if (!hash)
                    throw new DOMException(
                        `Failed to execute 'verify' on 'SubtleCrypto': EcdsaParams: hash: Algorithm: Unrecognized name`,
                        'NotSupportedError',
                    )
                const hashed = await nativeSubtle.digest(hash, data)
                return verifyK256(get(key), hashed, new Uint8Array(signature as ArrayBuffer))
            }
            return nativeSubtle.verify(algorithm, key, signature, data)
        },
        //#endregion
        //#region Create, Import, Export
        async generateKey(algorithm, extractable, keyUsages) {
            const k256Name = isK256Alg(algorithm, 'any')
            if (k256Name) {
                const _ = generateK256Pair(k256Name, extractable, keyUsages, DOMException)
                return { publicKey: newKey(_.pub), privateKey: newKey(_.priv) }
            }
            return (nativeSubtle.generateKey as any)(algorithm, extractable, keyUsages) as any
        },
        async importKey(format, keyData, algorithm, extractable, keyUsages) {
            const k256Name = isK256Alg(algorithm, 'any')
            if (k256Name) {
                const usageFlag = usageToFlag(k256Name, keyUsages, DOMException)
                if (format === 'pkcs8') {
                    throw new DOMException('The key is not of the expected type', 'InvalidAccessError')
                }
                // TODO: support spki
                if (format === 'spki') {
                    throw new DOMException('spki export of K-256 keys is not supported', 'NotSupportedError')
                }
                if (format === 'jwk' || format === 'raw') {
                    return newKey(importK256(format, k256Name, keyData, extractable, usageFlag, DOMException))
                }
                throw new TypeError('Invalid keyFormat argument')
            }
            return nativeSubtle.importKey(format as any, keyData as any, algorithm, extractable, keyUsages)
        },
        async exportKey(format, key) {
            if (has(key)) {
                if (format === 'pkcs8') {
                    throw new DOMException('The key is not of the expected type', 'InvalidAccessError')
                }
                // TODO: support spki
                if (format === 'spki') {
                    throw new DOMException('spki export of K-256 keys is not supported', 'NotSupportedError')
                }
                if (format === 'jwk' || format === 'raw') return exportK256(format, get(key))

                throw new TypeError('Invalid keyFormat argument')
            }
            return nativeSubtle.exportKey(format as any, key) as any
        },
        //#endregion
    }
    return [ShimCryptoKey, shimSubtleCrypto] as const
}
