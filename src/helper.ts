/** @internal */
export type Name = 'ECDH' | 'ECDSA'
/** @internal */
export type Hash = 'SHA-256' | 'SHA-384' | 'SHA-512'
/** @internal */
export function isK256Alg(alg: unknown, acceptKind: 'ECDH' | 'ECDSA' | 'any'): Name | undefined {
    try {
        if (typeof alg !== 'object') return
        if (alg === null) return
        const { name, namedCurve } = alg as EcKeyAlgorithm
        if (namedCurve !== 'K-256') return
        if (acceptKind === 'any') {
            if (name === 'ECDH' || name === 'ECDSA') return name
        } else {
            if (name === acceptKind) return name
        }
        return
    } catch {
        return
    }
}
/** @internal */
export function getHashAlg(alg: unknown): Hash | undefined {
    try {
        const { name } = (alg as any).hash
        if (name === 'SHA-256') return name
        if (name === 'SHA-384') return name
        if (name === 'SHA-512') return name
        return
    } catch {
        return
    }
}

// https://github.com/PeculiarVentures/webcrypto-liner/blob/3a97b53b7f187f776ea5b23889e03c3f54654811/src/mechs/ec/crypto.ts#L56
/** @internal */
export function b2a(buffer: ArrayBuffer | ArrayBufferView) {
    const buf = new Uint8Array(buffer as ArrayBuffer)
    const res: number[] = []
    for (let i = 0; i < buf.length; i++) {
        res.push(buf[i])
    }
    return res
}

/** @internal */
export function concat(...buf: (Uint8Array | number[])[]) {
    const res = new Uint8Array(buf.map((item) => item.length).reduce((prev, cur) => prev + cur))
    let offset = 0
    buf.forEach((item, index) => {
        for (let i = 0; i < item.length; i++) {
            res[offset + i] = item[i]
        }
        offset += item.length
    })
    return res
}

/** @internal */
export function hex2buffer(hexString: string, padded?: boolean) {
    if (hexString.length % 2) {
        hexString = '0' + hexString
    }
    let res = new Uint8Array(hexString.length / 2)
    for (let i = 0; i < hexString.length; i++) {
        const c = hexString.slice(i, ++i + 1)
        res[(i - 1) / 2] = parseInt(c, 16)
    }
    // BN padding
    if (padded) {
        let len = res.length
        len = len > 32 ? (len > 48 ? 66 : 48) : 32
        if (res.length < len) {
            res = concat(new Uint8Array(len - res.length), res)
        }
    }
    return res
}

/** @internal */
export function buffer2hex(buffer: Uint8Array | number[], padded?: boolean): string {
    let res = ''
    // tslint:disable-next-line:prefer-for-of
    for (let i = 0; i < buffer.length; i++) {
        const char = buffer[i].toString(16)
        res += char.length % 2 ? '0' + char : char
    }

    // BN padding
    if (padded) {
        let len = buffer.length
        len = len > 32 ? (len > 48 ? 66 : 48) : 32
        if (res.length / 2 < len) {
            res = new Array(len * 2 - res.length + 1).join('0') + res
        }
    }

    return res
}
