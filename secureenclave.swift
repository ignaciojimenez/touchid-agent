import Foundation
import CryptoKit
import Security

private func writeBytes(
    _ data: Data,
    _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>
) {
    let count = data.count
    let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
    data.copyBytes(to: buf, count: count)
    outPtr.pointee = buf
    outLen.pointee = count
}

private func writeError(
    _ message: String,
    _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) {
    outPtr.pointee = strdup(message)
}

@_cdecl("se_generate")
public func se_generate(
    require_touch: Int32,
    key_data_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    key_data_len: UnsafeMutablePointer<Int>,
    pubkey_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    pubkey_len: UnsafeMutablePointer<Int>,
    error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if require_touch != 0 { flags.insert(.biometryAny) }

    var cfErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        &cfErr
    ) else {
        let msg = (cfErr?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? "SecAccessControlCreateWithFlags failed"
        writeError(msg, error_out)
        return -1
    }

    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        writeBytes(key.dataRepresentation, key_data_out, key_data_len)
        writeBytes(key.publicKey.x963Representation, pubkey_out, pubkey_len)
        return 0
    } catch {
        writeError("\(error)", error_out)
        return -1
    }
}

@_cdecl("se_public_key")
public func se_public_key(
    key_data: UnsafePointer<UInt8>,
    key_data_len: Int,
    pubkey_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    pubkey_len: UnsafeMutablePointer<Int>,
    error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    do {
        let blob = Data(bytes: key_data, count: key_data_len)
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        writeBytes(key.publicKey.x963Representation, pubkey_out, pubkey_len)
        return 0
    } catch {
        writeError("\(error)", error_out)
        return -1
    }
}

// CryptoKit's signature(for: D where D: DataProtocol) hashes the input with
// SHA-256 before signing. The agent layer hands us an already-hashed digest,
// so we route through the signature(for: D where D: Digest) overload via
// this minimal Digest conformer to avoid double-hashing.
private struct PrehashedDigest: Digest {
    static var byteCount: Int { 32 }
    let bytes: [UInt8]

    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    var description: String { "PrehashedDigest" }
    static func == (lhs: PrehashedDigest, rhs: PrehashedDigest) -> Bool { lhs.bytes == rhs.bytes }
}

@_cdecl("se_sign")
public func se_sign(
    key_data: UnsafePointer<UInt8>,
    key_data_len: Int,
    digest: UnsafePointer<UInt8>,
    digest_len: Int,
    sig_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    sig_len: UnsafeMutablePointer<Int>,
    error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    guard digest_len == 32 else {
        writeError("digest must be 32 bytes (SHA-256), got \(digest_len)", error_out)
        return -1
    }
    do {
        let blob = Data(bytes: key_data, count: key_data_len)
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        let dig = PrehashedDigest(bytes: Array(UnsafeBufferPointer(start: digest, count: digest_len)))
        let sig = try key.signature(for: dig)
        writeBytes(sig.derRepresentation, sig_out, sig_len)
        return 0
    } catch {
        writeError("\(error)", error_out)
        return -1
    }
}

// MARK: - Software backend
//
// Software keys never reach the SEP. CryptoKit generates and signs in
// process memory, the rawRepresentation is a 32-byte private scalar
// the agent persists at rest. There is no biometric gate on these keys
// (see spec section 3.6); they are the escape hatch for ad-hoc-signed
// builds and machines without a Secure Enclave.

@_cdecl("sw_generate")
public func sw_generate(
    key_data_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    key_data_len: UnsafeMutablePointer<Int>,
    pubkey_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    pubkey_len: UnsafeMutablePointer<Int>,
    error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    let key = P256.Signing.PrivateKey()
    writeBytes(key.rawRepresentation, key_data_out, key_data_len)
    writeBytes(key.publicKey.x963Representation, pubkey_out, pubkey_len)
    return 0
}

@_cdecl("sw_sign")
public func sw_sign(
    key_data: UnsafePointer<UInt8>,
    key_data_len: Int,
    digest: UnsafePointer<UInt8>,
    digest_len: Int,
    sig_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    sig_len: UnsafeMutablePointer<Int>,
    error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    guard digest_len == 32 else {
        writeError("digest must be 32 bytes (SHA-256), got \(digest_len)", error_out)
        return -1
    }
    do {
        let blob = Data(bytes: key_data, count: key_data_len)
        let key = try P256.Signing.PrivateKey(rawRepresentation: blob)
        let dig = PrehashedDigest(bytes: Array(UnsafeBufferPointer(start: digest, count: digest_len)))
        let sig = try key.signature(for: dig)
        writeBytes(sig.derRepresentation, sig_out, sig_len)
        return 0
    } catch {
        writeError("\(error)", error_out)
        return -1
    }
}
