import { concat } from '../helper.js'
import type { KeyMaterial } from '../key.js'

/** @internal */
export function deriveBitsK256(pub: KeyMaterial, priv: KeyMaterial, length: number) {
    const derived = priv.key.derive(pub.key.getPublic())
    let array = new Uint8Array(derived.toArray())

    // Padding
    let len = array.length
    len = len > 32 ? (len > 48 ? 66 : 48) : 32
    if (array.length < len) {
        array = concat(new Uint8Array(len - array.length), array)
    }
    const buf = array.slice(0, length / 8).buffer
    return buf
}
