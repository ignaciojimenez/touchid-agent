#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include "secureenclave.h"
#include <stdlib.h>
#include <string.h>

static char *cferror_string(CFErrorRef error) {
    if (!error) return strdup("unknown error");
    CFStringRef desc = CFErrorCopyDescription(error);
    CFIndex len = CFStringGetMaximumSizeForEncoding(
        CFStringGetLength(desc), kCFStringEncodingUTF8) + 1;
    char *buf = (char *)malloc(len);
    CFStringGetCString(desc, buf, len, kCFStringEncodingUTF8);
    CFRelease(desc);
    return buf;
}

static char *osstatus_string(OSStatus status) {
    CFStringRef msg = SecCopyErrorMessageString(status, NULL);
    if (!msg) {
        char *buf = (char *)malloc(64);
        snprintf(buf, 64, "OSStatus %d", (int)status);
        return buf;
    }
    CFIndex len = CFStringGetMaximumSizeForEncoding(
        CFStringGetLength(msg), kCFStringEncodingUTF8) + 1;
    char *buf = (char *)malloc(len);
    CFStringGetCString(msg, buf, len, kCFStringEncodingUTF8);
    CFRelease(msg);
    return buf;
}

static SecKeyRef find_private_key(const char *tag, char **error_out) {
    @autoreleasepool {
        NSData *tagData = [[NSString stringWithUTF8String:tag]
                           dataUsingEncoding:NSUTF8StringEncoding];

        NSDictionary *query = @{
            (id)kSecClass:              (id)kSecClassKey,
            (id)kSecAttrApplicationTag: tagData,
            (id)kSecAttrKeyType:        (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeyClass:       (id)kSecAttrKeyClassPrivate,
            (id)kSecReturnRef:          @YES,
            (id)kSecMatchLimit:         (id)kSecMatchLimitOne,
        };

        SecKeyRef key = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query,
                                              (CFTypeRef *)&key);
        if (status != errSecSuccess) {
            *error_out = osstatus_string(status);
            return NULL;
        }
        return key;
    }
}

int se_generate_key(const char *label, const char *tag, int require_touch,
                    int use_se, char **error_out) {
    @autoreleasepool {
        NSData *tagData = [[NSString stringWithUTF8String:tag]
                           dataUsingEncoding:NSUTF8StringEncoding];
        NSString *labelStr = [NSString stringWithUTF8String:label];

        NSMutableDictionary *privAttrs = [@{
            (id)kSecAttrIsPermanent:    @YES,
            (id)kSecAttrApplicationTag: tagData,
            (id)kSecAttrLabel:          labelStr,
        } mutableCopy];

        if (use_se || require_touch) {
            SecAccessControlCreateFlags flags = 0;
            if (use_se) {
                flags |= kSecAccessControlPrivateKeyUsage;
            }
            if (require_touch) {
                flags |= kSecAccessControlBiometryAny;
            }

            CFErrorRef cfErr = NULL;
            SecAccessControlRef access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                flags,
                &cfErr);

            if (!access) {
                *error_out = cferror_string(cfErr);
                if (cfErr) CFRelease(cfErr);
                [privAttrs release];
                return -1;
            }
            privAttrs[(id)kSecAttrAccessControl] = (__bridge id)access;
            CFRelease(access);
        }

        NSMutableDictionary *attrs = [@{
            (id)kSecAttrKeyType:       (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @256,
            (id)kSecPrivateKeyAttrs:   privAttrs,
        } mutableCopy];

        if (use_se) {
            attrs[(id)kSecAttrTokenID] = (id)kSecAttrTokenIDSecureEnclave;
        }

        CFErrorRef cfErr = NULL;
        SecKeyRef privateKey = SecKeyCreateRandomKey(
            (__bridge CFDictionaryRef)attrs, &cfErr);
        [privAttrs release];
        [attrs release];

        if (!privateKey) {
            *error_out = cferror_string(cfErr);
            if (cfErr) CFRelease(cfErr);
            return -1;
        }

        CFRelease(privateKey);
        return 0;
    }
}

int se_sign(const char *tag, const uint8_t *digest, size_t digest_len,
            uint8_t **sig_out, size_t *sig_len, char **error_out) {
    @autoreleasepool {
        SecKeyRef privateKey = find_private_key(tag, error_out);
        if (!privateKey) return -1;

        CFDataRef digestData = CFDataCreate(NULL, digest, digest_len);
        CFErrorRef cfErr = NULL;
        CFDataRef signature = SecKeyCreateSignature(
            privateKey,
            kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
            digestData,
            &cfErr);

        CFRelease(digestData);
        CFRelease(privateKey);

        if (!signature) {
            *error_out = cferror_string(cfErr);
            if (cfErr) CFRelease(cfErr);
            return -1;
        }

        *sig_len = (size_t)CFDataGetLength(signature);
        *sig_out = (uint8_t *)malloc(*sig_len);
        memcpy(*sig_out, CFDataGetBytePtr(signature), *sig_len);
        CFRelease(signature);
        return 0;
    }
}

int se_get_public_key(const char *tag, uint8_t **pub_out, size_t *pub_len,
                      char **error_out) {
    @autoreleasepool {
        SecKeyRef privateKey = find_private_key(tag, error_out);
        if (!privateKey) return -1;

        SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
        CFRelease(privateKey);

        if (!publicKey) {
            *error_out = strdup("failed to derive public key");
            return -1;
        }

        CFErrorRef cfErr = NULL;
        CFDataRef pubData = SecKeyCopyExternalRepresentation(publicKey, &cfErr);
        CFRelease(publicKey);

        if (!pubData) {
            *error_out = cferror_string(cfErr);
            if (cfErr) CFRelease(cfErr);
            return -1;
        }

        *pub_len = (size_t)CFDataGetLength(pubData);
        *pub_out = (uint8_t *)malloc(*pub_len);
        memcpy(*pub_out, CFDataGetBytePtr(pubData), *pub_len);
        CFRelease(pubData);
        return 0;
    }
}

int se_list_keys(const char *tag_prefix, char **result_out, char **error_out) {
    @autoreleasepool {
        NSData *prefixData = [[NSString stringWithUTF8String:tag_prefix]
                              dataUsingEncoding:NSUTF8StringEncoding];

        NSDictionary *query = @{
            (id)kSecClass:              (id)kSecClassKey,
            (id)kSecAttrKeyType:        (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeyClass:       (id)kSecAttrKeyClassPrivate,
            (id)kSecReturnAttributes:   @YES,
            (id)kSecReturnRef:          @YES,
            (id)kSecMatchLimit:         (id)kSecMatchLimitAll,
        };

        CFArrayRef items = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query,
                                              (CFTypeRef *)&items);

        if (status == errSecItemNotFound) {
            *result_out = strdup("");
            return 0;
        }
        if (status != errSecSuccess) {
            *error_out = osstatus_string(status);
            return -1;
        }

        NSArray *results = (__bridge NSArray *)items;
        NSMutableString *output = [NSMutableString string];
        NSString *prefix = [NSString stringWithUTF8String:tag_prefix];

        for (NSDictionary *item in results) {
            NSData *tagData = item[(id)kSecAttrApplicationTag];
            if (!tagData) continue;

            NSString *tag = [[NSString alloc] initWithData:tagData
                                                  encoding:NSUTF8StringEncoding];
            if (!tag || ![tag hasPrefix:prefix]) {
                [tag release];
                continue;
            }

            NSString *label = item[(id)kSecAttrLabel];
            if (!label) label = @"";

            [output appendFormat:@"%@\t%@\n", tag, label];
            [tag release];
        }

        CFRelease(items);
        *result_out = strdup([output UTF8String]);
        return 0;
    }
}

int se_delete_key(const char *tag, char **error_out) {
    @autoreleasepool {
        NSData *tagData = [[NSString stringWithUTF8String:tag]
                           dataUsingEncoding:NSUTF8StringEncoding];

        NSDictionary *query = @{
            (id)kSecClass:              (id)kSecClassKey,
            (id)kSecAttrApplicationTag: tagData,
            (id)kSecAttrKeyType:        (id)kSecAttrKeyTypeECSECPrimeRandom,
        };

        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        if (status != errSecSuccess && status != errSecItemNotFound) {
            *error_out = osstatus_string(status);
            return -1;
        }
        return 0;
    }
}

int se_delete_all_keys(const char *tag_prefix, char **error_out) {
    @autoreleasepool {
        char *list = NULL;
        if (se_list_keys(tag_prefix, &list, error_out) != 0) {
            return -1;
        }

        if (strlen(list) == 0) {
            free(list);
            return 0;
        }

        char *line = strtok(list, "\n");
        while (line) {
            char *tab = strchr(line, '\t');
            if (tab) {
                *tab = '\0';
                char *err = NULL;
                se_delete_key(line, &err);
                if (err) free(err);
            }
            line = strtok(NULL, "\n");
        }

        free(list);
        return 0;
    }
}


