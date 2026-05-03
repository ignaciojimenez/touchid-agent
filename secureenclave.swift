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
