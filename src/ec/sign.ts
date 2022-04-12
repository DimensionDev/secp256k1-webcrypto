import { b2a, buffer2hex, hex2buffer } from '../helper.js'
import type { KeyMaterial } from '../key.js'

export function signK256(key: KeyMaterial, hash: BufferSource): ArrayBuffer {
    if (key.type !== 'private') throw new Error()
    if (key.name !== 'ECDSA') throw new Error()

    const array = b2a(hash)
    const sig = key.key.sign(array)
    const hexSignature = buffer2hex(sig.r.toArray(), true) + buffer2hex(sig.s.toArray(), true)
    return hex2buffer(hexSignature).buffer
}
export function verifyK256(key: KeyMaterial, hash: BufferSource, signature: Uint8Array): boolean {
    if (key.name !== 'ECDSA') throw new Error()

    const sig = {
        r: new Uint8Array(signature.slice(0, signature.byteLength / 2)),
        s: new Uint8Array(signature.slice(signature.byteLength / 2)),
    }
    const array = b2a(hash)
    return key.key.verify(array, sig)
}
