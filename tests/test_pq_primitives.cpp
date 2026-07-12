// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// KAT-based tests for the PQ Phase 1 crypto primitives. Vectors:
//   * SHA3-256          : FIPS 202 known answers (empty / "abc")
//   * HMAC-SHA3-256     : NIST CAVP "Jefe / what do ya want for nothing?"
//   * HKDF-SHA3-256     : internal consistency + length-extension
//   * ChaCha20-Poly1305 : RFC 8439 §2.8.2 (the canonical AEAD KAT)
//   * ML-KEM-768        : encaps/decaps round-trip, deterministic keygen,
//                         FIPS 203 implicit-rejection on garbage ciphertext
//   * ML-DSA-65         : sign/verify round-trip, deterministic keygen,
//                         signature/message/key tamper rejection
//
// liboqs's own KAT suite covers the lattice primitives byte-exactly against
// the FIPS 203 / 204 reference vectors; we focus here on (a) round-trip
// correctness through our wrappers and (b) determinism of the seed-driven
// keygens that Karbo PQ depends on.

#include "gtest/gtest.h"

#include "crypto_pq/PqHash.h"
#include "crypto_pq/PqAead.h"
#include "crypto_pq/PqKem.h"
#include "crypto_pq/PqDsa.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

extern "C" {
#include <oqs/kem_ml_kem.h>
}

namespace {

std::string to_hex(const uint8_t* data, std::size_t len) {
    static const char* h = "0123456789abcdef";
    std::string out;
    out.reserve(2 * len);
    for (std::size_t i = 0; i < len; ++i) {
        out += h[data[i] >> 4];
        out += h[data[i] & 0xf];
    }
    return out;
}

template <std::size_t N>
std::string to_hex(const std::array<uint8_t, N>& a) {
    return to_hex(a.data(), N);
}

uint8_t hex_nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    throw std::runtime_error("invalid test-vector hex");
}

template <std::size_t N>
std::array<uint8_t, N> from_hex(const std::string& hex) {
    if (hex.size() != 2 * N) throw std::runtime_error("wrong test-vector length");
    std::array<uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = static_cast<uint8_t>((hex_nibble(hex[2 * i]) << 4) |
                                      hex_nibble(hex[2 * i + 1]));
    }
    return out;
}

}  // namespace

// ===========================================================================
// SHA3-256 — FIPS 202 known answers
// ===========================================================================

TEST(PqHash_Sha3_256, FIPS_202_Empty) {
    auto h = CryptoPQ::sha3_256("", 0);
    EXPECT_EQ(to_hex(h),
              "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

TEST(PqHash_Sha3_256, FIPS_202_Abc) {
    auto h = CryptoPQ::sha3_256("abc", 3);
    EXPECT_EQ(to_hex(h),
              "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
}

// ===========================================================================
// HMAC-SHA3-256 — NIST CAVP-style vector
//
// Same key/message convention as RFC 4231 Test Case 2, applied with SHA-3.
// ===========================================================================

TEST(PqHash_Hmac, NIST_Jefe_WhatDoYaWant) {
    const char* key = "Jefe";
    const char* msg = "what do ya want for nothing?";
    auto h = CryptoPQ::hmac_sha3_256(key, 4, msg, std::strlen(msg));
    EXPECT_EQ(to_hex(h),
              "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5");
}

TEST(PqHash_Hmac, EmptyKeyEmptyMsgIsDeterministic) {
    // We deliberately do NOT hardcode the expected value here: NIST has
    // not published a HMAC-SHA3-256 KAT for the empty/empty case in a
    // form we can cite verbatim, and the well-known Jefe KAT above is
    // already strong external evidence the construction is correct.
    // This test instead asserts that the empty/empty result is stable
    // (same call twice → same bytes), which catches accidental state
    // pollution between invocations.
    auto h1 = CryptoPQ::hmac_sha3_256("", 0, "", 0);
    auto h2 = CryptoPQ::hmac_sha3_256("", 0, "", 0);
    EXPECT_EQ(h1, h2);
}

// ===========================================================================
// HKDF-SHA3-256 — internal consistency
// ===========================================================================

TEST(PqHash_Hkdf, DefaultIsDeterministic) {
    uint8_t ikm[32] = {0};
    ikm[0] = 1; ikm[31] = 0xff;
    auto a = CryptoPQ::hkdf_sha3_256(ikm, sizeof(ikm), "info", 4);
    auto b = CryptoPQ::hkdf_sha3_256(ikm, sizeof(ikm), "info", 4);
    EXPECT_EQ(a, b);
}

TEST(PqHash_Hkdf, InfoChangesOutput) {
    uint8_t ikm[32] = {0};
    auto a = CryptoPQ::hkdf_sha3_256(ikm, sizeof(ikm), "info1", 5);
    auto b = CryptoPQ::hkdf_sha3_256(ikm, sizeof(ikm), "info2", 5);
    EXPECT_NE(a, b);
}

TEST(PqHash_Hkdf, IkmChangesOutput) {
    uint8_t ikm1[32] = {0}; ikm1[0] = 1;
    uint8_t ikm2[32] = {0}; ikm2[0] = 2;
    auto a = CryptoPQ::hkdf_sha3_256(ikm1, sizeof(ikm1), "x", 1);
    auto b = CryptoPQ::hkdf_sha3_256(ikm2, sizeof(ikm2), "x", 1);
    EXPECT_NE(a, b);
}

TEST(PqHash_Hkdf, ExpandToL96MatchesL32Prefix) {
    // HKDF-Expand: T(1) is the first 32 bytes regardless of total L,
    // so an L=96 expansion's first 32 bytes must equal the L=32 default.
    uint8_t ikm[32] = {0xab};
    std::vector<uint8_t> okm(96);
    bool ok = CryptoPQ::hkdf_sha3_256_explicit(
        ikm, sizeof(ikm), nullptr, 0, "extend", 6,
        okm.data(), okm.size());
    ASSERT_TRUE(ok);
    auto h32 = CryptoPQ::hkdf_sha3_256(ikm, sizeof(ikm), "extend", 6);
    EXPECT_EQ(0, std::memcmp(okm.data(), h32.data(), 32));
}

TEST(PqHash_Hkdf, ExpandTooLargeRejected) {
    uint8_t ikm[1] = {0};
    // RFC 5869 caps L at 255 * HashLen.
    std::vector<uint8_t> okm(255 * 32 + 1);
    bool ok = CryptoPQ::hkdf_sha3_256_explicit(
        ikm, 1, nullptr, 0, "x", 1, okm.data(), okm.size());
    EXPECT_FALSE(ok);
}

TEST(PqHash_Hkdf, ZeroLengthRejected) {
    uint8_t ikm[1] = {0};
    uint8_t okm[1];
    bool ok = CryptoPQ::hkdf_sha3_256_explicit(
        ikm, 1, nullptr, 0, "x", 1, okm, 0);
    EXPECT_FALSE(ok);
}

TEST(PqHash_Hkdf, ExplicitZeroSaltMatchesNullSalt) {
    // RFC 5869 §2.2: empty salt should be treated as HashLen zero bytes.
    // Our wrapper does this automatically when salt==nullptr; an explicit
    // 32-byte zero salt must produce the same output.
    uint8_t ikm[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t zero_salt[32] = {0};
    uint8_t a[32], b[32];
    ASSERT_TRUE(CryptoPQ::hkdf_sha3_256_explicit(
        ikm, sizeof(ikm), nullptr, 0, "info", 4, a, sizeof(a)));
    ASSERT_TRUE(CryptoPQ::hkdf_sha3_256_explicit(
        ikm, sizeof(ikm), zero_salt, sizeof(zero_salt), "info", 4, b, sizeof(b)));
    EXPECT_EQ(0, std::memcmp(a, b, 32));
}

// ===========================================================================
// ChaCha20-Poly1305 IETF — RFC 8439 §2.8.2 KAT
// ===========================================================================

TEST(PqAead, RFC8439_Section_2_8_2) {
    const std::string plaintext =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    ASSERT_EQ(plaintext.size(), 114u);

    CryptoPQ::AeadKey key{
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    CryptoPQ::AeadNonce nonce{
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    };
    const uint8_t aad[] = {
        0x50, 0x51, 0x52, 0x53,
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    };

    const std::string expected_ct =
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca967128 2fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3"
        "692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7b"
        "c3ff4def08e4b7a9de576d26586cec64b6116";
    // Strip whitespace from the literal above (compile-time formatting).
    std::string expected_ct_clean;
    for (char c : expected_ct) if (c != ' ') expected_ct_clean += c;
    const std::string expected_tag = "1ae10b594f09e26a7e902ecbd0600691";

    auto out = CryptoPQ::aead_encrypt(
        key, nonce,
        aad, sizeof(aad),
        plaintext.data(), plaintext.size());

    ASSERT_EQ(out.size(), plaintext.size() + 16);
    EXPECT_EQ(to_hex(out.data(), plaintext.size()), expected_ct_clean);
    EXPECT_EQ(to_hex(out.data() + plaintext.size(), 16), expected_tag);

    // Round-trip
    auto opt = CryptoPQ::aead_decrypt(
        key, nonce,
        aad, sizeof(aad),
        out.data(), out.size());
    ASSERT_TRUE(opt.has_value());
    EXPECT_EQ(std::string(opt->begin(), opt->end()), plaintext);
}

TEST(PqAead, TamperedTagRejected) {
    CryptoPQ::AeadKey   key{};
    CryptoPQ::AeadNonce nonce{};
    auto out = CryptoPQ::aead_encrypt(key, nonce, nullptr, 0, "hi", 2);
    out.back() ^= 0x01;  // flip a bit in the tag
    auto opt = CryptoPQ::aead_decrypt(key, nonce, nullptr, 0, out.data(), out.size());
    EXPECT_FALSE(opt.has_value());
}

TEST(PqAead, TamperedCiphertextRejected) {
    CryptoPQ::AeadKey   key{};
    CryptoPQ::AeadNonce nonce{};
    auto out = CryptoPQ::aead_encrypt(key, nonce, nullptr, 0, "hello", 5);
    out[0] ^= 0x01;  // flip a bit in the ciphertext
    auto opt = CryptoPQ::aead_decrypt(key, nonce, nullptr, 0, out.data(), out.size());
    EXPECT_FALSE(opt.has_value());
}

TEST(PqAead, TamperedAadRejected) {
    CryptoPQ::AeadKey   key{};
    CryptoPQ::AeadNonce nonce{};
    const uint8_t aad_enc[] = {1, 2, 3};
    const uint8_t aad_dec[] = {1, 2, 4};
    auto out = CryptoPQ::aead_encrypt(key, nonce, aad_enc, sizeof(aad_enc), "hi", 2);
    auto opt = CryptoPQ::aead_decrypt(key, nonce, aad_dec, sizeof(aad_dec), out.data(), out.size());
    EXPECT_FALSE(opt.has_value());
}

TEST(PqAead, EmptyMessageOk) {
    CryptoPQ::AeadKey   key{};
    CryptoPQ::AeadNonce nonce{};
    auto out = CryptoPQ::aead_encrypt(key, nonce, nullptr, 0, nullptr, 0);
    EXPECT_EQ(out.size(), 16u);  // tag only
    auto opt = CryptoPQ::aead_decrypt(key, nonce, nullptr, 0, out.data(), out.size());
    ASSERT_TRUE(opt.has_value());
    EXPECT_TRUE(opt->empty());
}

// ===========================================================================
// ML-KEM-768
// ===========================================================================

TEST(PqKem_768, EncapsDecapsRoundTrip) {
    auto [pub, sk] = CryptoPQ::kem_keygen();
    auto [ct, ss_send] = CryptoPQ::kem_encaps(pub);
    auto ss_recv = CryptoPQ::kem_decaps(sk, ct);
    EXPECT_EQ(ss_send, ss_recv);
}

TEST(PqKem_768, ExplicitMessageEncapsDecapsRoundTrip) {
    auto [pub, sk] = CryptoPQ::kem_keygen();
    CryptoPQ::KemEncapsMessage message{};
    for (std::size_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<uint8_t>(3 * i + 1);
    }
    auto [ct, ss_send] = CryptoPQ::kem_encaps_explicit(pub, message);
    EXPECT_EQ(ss_send, CryptoPQ::kem_decaps(sk, ct));
}

// NIST ACVP Server internal projection, ML-KEM-768 encapsulation tgId 2,
// tcId 26. This pins the application wrapper byte-for-byte to FIPS 203
// Encaps_Internal rather than merely checking self-consistency.
TEST(PqKem_768, NistAcvpExplicitEncapsulation) {
    const std::string ekHex =
        "B649B9AD5A59AA45640B03ACE153499BC1244465735DCA6E5ED0C7116070287758E7A31EE53BA171E7C8964B3615075286A4AF1EA12479AB"
        "0218608692A2606A024D12FCAE691C8114828F3547C9D0344AF9920D952BA6BCE6AAE6A47360DA1588697F91AB5475C5588AD6328389A34B"
        "A50E41514343C534AD7947C5AA4220C73D335BB24F6676CC2549FD40759CD4B54549B04D8932921B183ECB634B579A54742DD6734C722574"
        "1BA32AC196AA68FAAF3D1425D4A44CC563AAF8816A8258BF745842F1CA7D8EDA9A7A6CCD72966ABAB9061EE21EF3D2B1155133F4B8099B65"
        "3BA8B5224360CF00295F2B3887D1B12D601B18BD407B80D167AEFA0D3F6A906FC2CD08A663B7766815A26C6E2BC83318AC99B5A56D338EC3"
        "47ADBD9A57EC53359CE898FB637B32FC4A6FC216BFA30EEC501681751BEE46C5C02317C3B3B98F24AC67ACC53941CD20035FE2A59890E9AB"
        "7CF063FE07A62703643E0580D99C152343C5BDD8CB9F9C1FD0C194EE7281913A7D1F0473722C024DF76568A731D309CD5FA87FB3A0C771AA"
        "42EFD160AF89752C1C3EEAC74A934B163AF92D4EE74C709A31E901045FE6202DE9622B552ACD807829F46AD9C47087E2856F294B97546103"
        "568292A4B7462895F161891AF4A66D537E79087F87F63E4E5A7D767A5D6A4A52267C8CE41413EF6C3DC4B1C64EE5AD75D9542099361EF812"
        "46A64AD997885FE0631D02919AB6B967B8C441D73B67D52B5FA64AC7789D30E659D776334DA3A65A3B4081014455BC858637B23A991FE8EC"
        "315C687C36D81553C79F159C2B4B285604C0541AB62749CBA6C29472B5DC6AB61B2BE2E6A57A1942E729C1E95BA95C8100D4554FCEDC0D73"
        "AC8023F736A94AC757B7B5108807A5EABA507B6F22E627EF325C0EF3B28123BE7882840B7A8EFCBA7E0D82434C330B37B7C7F546B123D460"
        "A0D0C58893A7E4664F49ACC9150A5DFBB71FBEF44374A987E3192BE4A50FC1F1160A0488844864532689E9F29D55366969E014B198692519"
        "77C34049437BB41B334C2DE7A2EB63CC3FF21B042AA0E6839469E4BFA226CDBF8331CD1640E04B4CF2A89BFFC20283DC2D90706604C10211"
        "53417B26C650B483856463DF2C2C064AB4A9F316C5BA02109B1023370DDED31AB1DA2EB837BD8CCC52106712EB91A019119BD60951B3662F"
        "3F6291ECB76561B253DC4A1CB8E41B3A16B2EC87A252C4B747448823902845527B31C15A3EF18E174B644F548FAF30B3DA5610EDCCB73E3A"
        "8714BBBDD668C14A9472718B34EFC545FFF2783F033F13FC1665BC324CA244F1E91851D8CE2DF2B388EA24B2CB8EAB400F5A8AC1D01442F7"
        "65688393CE21C4C63113BA49480B247C3FB4D49DF82B1F493430BFA78F6D948DA4E927BDD9BD2D18A7F230046853BD8BE51CD59178D02955"
        "09213B7E1B0798584DCE835B48312F0257A185D9360E0A702AD8BB0A53C119336889974B8E52B636328556CA1A9EEC413F5259C66503C902"
        "06A7857925C727815C94FD545F0112C6A7E89C2EF54AE897A4B0792F98F5710CA174288658F5C8596C7807008369831135E1D50D5AC77F6A"
        "E9641DE0622BCA6A8E746700818C4A22A9AD30C9BC660117F3462617BAF392280DE09F5695B3CDDA5E931C5B521BDAA455C3D0F0F7375153"
        "A754ED9620DA68DD";
    const std::string dkHex =
        "0AF8CF210B1B442C963FEB4297F3A1C0513353F6808C8450B3C698A0F75034F9349591201C674FB835C6F9BA484376B15ABC27A0443CA7B2"
        "93602321717CA9EC4411D8A184032289B6398E07C34D46E05D8A10CF51984486FC90C5EBB08D23A740DB30E6C88E2CB0BA758590B413A3EA"
        "50583D885945053B66631547405F59A053FB6B9E57E2B7D9593D71615EAB21B78774B32A6C9FBCC3B845E48130D86AACBC6900295DBFAB17"
        "E9F532F6635B45216FC71727B9F2C67EE5619691BEC4A1B2BAA990445978EDA08A6AB0279460BD6A7590C66044079C8728A68A11A1469F81"
        "39572572E3E2B1A8A4226E9BAFE8F871E2C21695B20AA15BCB56A974B582CFC168838E75226717B398CC5B3DA780D4C5310F35C37D2376F7"
        "73A06AC0C2D8E524EC50ABC6D72E18F509027C3DC6D47DC7B28E52F779094458C8948623610FF9C045B865885E08A8D946235FE053B9E304"
        "2B152FC5A318B6B785D9919BB030467AC775C9EB56FA00135B3C5B7E14BB5522A281598D584425C0234F358A713E581EFB5A2CE1560D53A3"
        "6D48A8330E18C6C99BB7018275445BCF72C3A6A8DB27F90455DEA48F7858978004B672094F1CEB700C284205864DBBD61C5F68B59DF95E8B"
        "01258F630E2F302919E10551400602656CCBA21FB931C365EA6B79936D7743B59763433E24A337CC2443A067C5733205189C38502399FC2C"
        "A7B360050555D4F719EA677D06B134CBF35559784A5727629AD888EBF37D57E012DE56B9978B8CCDA395B2AC4B56443AD22053F382B40908"
        "8851C2146AEA2D4105D091FB91A5F63FBEBCC7BCA382B2046F47E20119506157AB9A2104A62AD82E100C8A99093B4F787809491268E19FED"
        "6AB4436A513294419DC5322E076B686719CDA59B891462FFE246D338767EE52A14E87A3BA99142291C62D42BBA2697E72B810D335E4D7987"
        "CB208EC2AA466D09BACAF407B62A6A71442EDABBA9FFE03CEFEB8AE84ABF0FAC3641C79479F67B6D04C98458A2CAE7CD817B6ACFA4B0C4A3"
        "A85104B610B746ADB75D817A9C104BB2D29BC9B0A948FE4682F1416BFE44000290AB22319EC0A531A89A9A5FB544EF72CE93B1CD0BC3056A"
        "C768E4C50804CB3DB4C2372F506D12649776175D127BB5EDB7C2D79A01E304A7ACB76F164C2143F6056FEACF9690700FE15EB2FAC559646C"
        "765C708248698218404080C0F1A35E7EC44969875A301CA59000289A685A31CC69E5F2285F9A260BDB8A1CB13B4467B98F782051DCB8F5E9"
        "1889581277A359BD279905ABCF9A1A452507B810171865821FC7FBCB7C0AB2FE651706C4478323ACF69A1F2FDC539B547B25BC9302D9C627"
        "2AB027852C1FF4C8B33357CD77730AD6160AAB68EDA2B532D8BC7C4061594044478569E1D7238D464F66B141D5CC3D9B67A7CF554DD4460D"
        "60265F8C0B5899B68D57073A034B0E0B6CB9391AB9A8EA75A0E19D86125B34AB885885839F726548D54D954061411801F5651F780CB74DDB"
        "A0471C33319772B8661ACAA9C6DAB97DD31A684288C84DC56F3193A8E2D7CB29D74044321E77F3A0B1C27CB056C16161A9E2D417E4020E99"
        "0BC9EA3ABEF2101D4D89AD5F390B2C81CB221429CE796F7DC890C0807008BCC0B649B9AD5A59AA45640B03ACE153499BC1244465735DCA6E"
        "5ED0C7116070287758E7A31EE53BA171E7C8964B3615075286A4AF1EA12479AB0218608692A2606A024D12FCAE691C8114828F3547C9D034"
        "4AF9920D952BA6BCE6AAE6A47360DA1588697F91AB5475C5588AD6328389A34BA50E41514343C534AD7947C5AA4220C73D335BB24F6676CC"
        "2549FD40759CD4B54549B04D8932921B183ECB634B579A54742DD6734C7225741BA32AC196AA68FAAF3D1425D4A44CC563AAF8816A8258BF"
        "745842F1CA7D8EDA9A7A6CCD72966ABAB9061EE21EF3D2B1155133F4B8099B653BA8B5224360CF00295F2B3887D1B12D601B18BD407B80D1"
        "67AEFA0D3F6A906FC2CD08A663B7766815A26C6E2BC83318AC99B5A56D338EC347ADBD9A57EC53359CE898FB637B32FC4A6FC216BFA30EEC"
        "501681751BEE46C5C02317C3B3B98F24AC67ACC53941CD20035FE2A59890E9AB7CF063FE07A62703643E0580D99C152343C5BDD8CB9F9C1F"
        "D0C194EE7281913A7D1F0473722C024DF76568A731D309CD5FA87FB3A0C771AA42EFD160AF89752C1C3EEAC74A934B163AF92D4EE74C709A"
        "31E901045FE6202DE9622B552ACD807829F46AD9C47087E2856F294B97546103568292A4B7462895F161891AF4A66D537E79087F87F63E4E"
        "5A7D767A5D6A4A52267C8CE41413EF6C3DC4B1C64EE5AD75D9542099361EF81246A64AD997885FE0631D02919AB6B967B8C441D73B67D52B"
        "5FA64AC7789D30E659D776334DA3A65A3B4081014455BC858637B23A991FE8EC315C687C36D81553C79F159C2B4B285604C0541AB62749CB"
        "A6C29472B5DC6AB61B2BE2E6A57A1942E729C1E95BA95C8100D4554FCEDC0D73AC8023F736A94AC757B7B5108807A5EABA507B6F22E627EF"
        "325C0EF3B28123BE7882840B7A8EFCBA7E0D82434C330B37B7C7F546B123D460A0D0C58893A7E4664F49ACC9150A5DFBB71FBEF44374A987"
        "E3192BE4A50FC1F1160A0488844864532689E9F29D55366969E014B19869251977C34049437BB41B334C2DE7A2EB63CC3FF21B042AA0E683"
        "9469E4BFA226CDBF8331CD1640E04B4CF2A89BFFC20283DC2D90706604C1021153417B26C650B483856463DF2C2C064AB4A9F316C5BA0210"
        "9B1023370DDED31AB1DA2EB837BD8CCC52106712EB91A019119BD60951B3662F3F6291ECB76561B253DC4A1CB8E41B3A16B2EC87A252C4B7"
        "47448823902845527B31C15A3EF18E174B644F548FAF30B3DA5610EDCCB73E3A8714BBBDD668C14A9472718B34EFC545FFF2783F033F13FC"
        "1665BC324CA244F1E91851D8CE2DF2B388EA24B2CB8EAB400F5A8AC1D01442F765688393CE21C4C63113BA49480B247C3FB4D49DF82B1F49"
        "3430BFA78F6D948DA4E927BDD9BD2D18A7F230046853BD8BE51CD59178D0295509213B7E1B0798584DCE835B48312F0257A185D9360E0A70"
        "2AD8BB0A53C119336889974B8E52B636328556CA1A9EEC413F5259C66503C90206A7857925C727815C94FD545F0112C6A7E89C2EF54AE897"
        "A4B0792F98F5710CA174288658F5C8596C7807008369831135E1D50D5AC77F6AE9641DE0622BCA6A8E746700818C4A22A9AD30C9BC660117"
        "F3462617BAF392280DE09F5695B3CDDA5E931C5B521BDAA455C3D0F0F7375153A754ED9620DA68DD6D0D1469801B55E3AEE59AA34B9097E9"
        "64BF39A8C8EA9526289E5F19D213E6BD6294966BBADD4259C7036C078207214BA15E55120960C4191162722B5E781907";
    const std::string messageHex = "7D5201502FAD05B1463BC2212D6AEC1C8503204C491F12D9366AE750144B7831";
    const std::string ciphertextHex =
        "04F4A18C69708A17F561778B2AC10D94380ABEA4A20835939C9015D78DAC41A5012CED1BED948AED6C79193F8B2FC6DEABD3B092EC33AE2F"
        "54778F1C54CE762A69521764E20C05BC2EF96992F463CA95D09DD588AF622C297BBD8805113E985388FC9E16FDA06B5EED42DA629D514F86"
        "ED84ACFF0A09418E720201B794B49D072DF15E7B7D6EC6D82379A212C71C7603A1C9BBE57FB1CB9A431DE1980ECADA0A4FBF5CACE9AD0CEE"
        "DBFDC40761839D9CC1C8590EB6335179075892A8015E04ECADAD37FDCD4644EC2284CF4CBB4620FBAB6055A163E3733E3A7747044B766EBC"
        "356436B33E28FA4E67B083592B05811361445C719F6AE8ADD4EF8CE145E3933CEE75D19E98BB964D58044B6DE2B46107F80C3D4690114CC8"
        "4FB0D3B3D4C3AF671EA7B833746B54FCE5CC761CA4FD20CD163AFA849E5797619C31144A74140ABE1C7540D1A3C557A9F23AF6E6E3523667"
        "FFD13B92444CD3BE01B1581CA0CF7A536CE4C073DC17DE955BA22E469BC1C0EC213B3B7CEDDFC47567A7ECFC2A58A6C2A3C2185563277866"
        "F8979BBB86AF844349C6021EB9926ACFE0188FD0F809E056A8E0A8AAA2A4208562E775EF60C56CADD6E26A9E52D60187BF6ED0565616020E"
        "0C2BFD79D961B1069FF261B2ABF40C9EE2A2C442877F4EDB8D9AD717CB434FED67EF2EACD629DA1CE78023548853EEAF7D998923DB7CEB01"
        "74E67875E787F398435DA84C26B478FF6BF785C4714BC6F8E91804E10CC699E1BE342C952D57D3C84654D603709F4F6BB596E022E2E6149C"
        "81025226B9925045FF365D83991F7D4C8693544CA7BA6DA60F8E4F6723C9F14AC48882556336ED88C20163544C55AB4238E510AA910B04F4"
        "45252D507AF02AD24E7467920C81F2D31A71A7241BE2726BB9F8B20BF2100633F616A1233801EB37597DDBE2DEF36EF0727515E7DA178DA7"
        "760A41EDF9FFE98FBAA3495A35025F2BD100B3D63E940BA7D997104AC67F653D0A24A2BA2C8A355AF1EE048CB116B1A492577CC7CF61226F"
        "BBBABD9CBB043839585F2E00AE673EE6BECAAF5DA7919921C90C74D5B8B173B8A1A650F379B3B5E5F1D04538B936FC2CD0D4F8B9DF9F5052"
        "ECD9E66602815B4F96586D038D5BD5A3E44BDE1EF9FF9CFCB6B9AECE3129EF1F026BEFD299A7A8AD324149B156BC5AB868099DF52A205610"
        "3432879B495B0655FC1FE8073B502F3F40D403548B1629118CE0EDD41558E4215E8E241A45637A3434BF070F17DAC885ED656F80783A4C47"
        "000464FE78B9DB0DBB55895E271D3376BF0C50CEC9A403A8729982DC5B9172B5E80A0EF03FA2A24873188F8022A6F9DA8CA4F2E24AA7E299"
        "87B1060ECFE0B08E039EE1F7FB55A0CD35A73B6C25DC26E469BBC2D034265DB5F74E644842BB99199F83947C97BF87532B37A8D40A06F8BC"
        "5508EFB117D11DFB07325D9482CDCE60AA34529546D4C8D8F98E3F5B34B5C757075FEE9C3443E0A1109253F5F0A905C571E5343B277E0636"
        "A5A46AB36BECF5672E93B712B9BC8E3CD3656CAD1B29C16E";
    const std::string sharedHex = "11B62291B1A9D307C8240D70BE0B45436DB445793173F6E79FCD2B273D7F3B01";

    const auto ek = from_hex<CryptoPQ::kKemPublicKeyBytes>(ekHex);
    const auto dk = from_hex<CryptoPQ::kKemSecretKeyBytes>(dkHex);
    const auto message = from_hex<CryptoPQ::kKemEncapsMessageBytes>(messageHex);
    const auto expectedCt = from_hex<CryptoPQ::kKemCiphertextBytes>(ciphertextHex);
    const auto expectedSs = from_hex<CryptoPQ::kKemSharedBytes>(sharedHex);

    const auto actual = CryptoPQ::kem_encaps_explicit(ek, message);
    EXPECT_EQ(expectedCt, actual.first);
    EXPECT_EQ(expectedSs, actual.second);
    EXPECT_EQ(expectedSs, CryptoPQ::kem_decaps(dk, expectedCt));
}
TEST(PqKem_768, ExplicitMessageIsDeterministicAndInputBound) {
    CryptoPQ::KemKeypairSeed seed1{};
    CryptoPQ::KemKeypairSeed seed2{};
    seed1[0] = 1;
    seed2[0] = 2;
    auto [pub1, sk1] = CryptoPQ::kem_keygen_from_seed(seed1);
    auto [pub2, sk2] = CryptoPQ::kem_keygen_from_seed(seed2);
    CryptoPQ::KemEncapsMessage message1{};
    CryptoPQ::KemEncapsMessage message2{};
    message1[0] = 7;
    message2[0] = 8;

    auto a = CryptoPQ::kem_encaps_explicit(pub1, message1);
    auto b = CryptoPQ::kem_encaps_explicit(pub1, message1);
    auto differentMessage = CryptoPQ::kem_encaps_explicit(pub1, message2);
    auto differentKey = CryptoPQ::kem_encaps_explicit(pub2, message1);

    EXPECT_EQ(a, b);
    EXPECT_NE(a.first, differentMessage.first);
    EXPECT_NE(a.second, differentMessage.second);
    EXPECT_NE(a.first, differentKey.first);
    EXPECT_NE(a.second, differentKey.second);
}

TEST(PqKem_768, ExplicitMessageRejectsNonCanonicalPublicKeyAndCleansesOutputs) {
    CryptoPQ::KemPublicKey invalid;
    invalid.fill(0xff);
    CryptoPQ::KemEncapsMessage message{};
    EXPECT_THROW((void)CryptoPQ::kem_encaps_explicit(invalid, message), std::runtime_error);

    CryptoPQ::KemCiphertext ct;
    CryptoPQ::KemShared ss;
    ct.fill(0xa5);
    ss.fill(0x5a);
    EXPECT_NE(OQS_SUCCESS, OQS_KEM_ml_kem_768_encaps_derand(
        ct.data(), ss.data(), invalid.data(), message.data()));
    EXPECT_EQ(CryptoPQ::KemCiphertext{}, ct);
    EXPECT_EQ(CryptoPQ::KemShared{}, ss);
}

TEST(PqKem_768, ExplicitMessageDoesNotShareRandomState) {
    CryptoPQ::KemKeypairSeed seed{};
    seed[0] = 0x42;
    auto [pub, sk] = CryptoPQ::kem_keygen_from_seed(seed);
    CryptoPQ::KemEncapsMessage message{};
    message[0] = 0x24;
    const auto expected = CryptoPQ::kem_encaps_explicit(pub, message);
    std::atomic<bool> ok{true};

    std::thread explicitThread([&] {
        for (int i = 0; i < 8; ++i) {
            if (CryptoPQ::kem_encaps_explicit(pub, message) != expected) ok = false;
        }
    });
    std::thread ordinaryThread([&] {
        for (int i = 0; i < 8; ++i) {
            auto enc = CryptoPQ::kem_encaps(pub);
            if (CryptoPQ::kem_decaps(sk, enc.first) != enc.second) ok = false;
        }
    });
    std::thread keygenThread([&] {
        for (int i = 0; i < 4; ++i) {
            auto kp = CryptoPQ::kem_keygen();
            auto enc = CryptoPQ::kem_encaps(kp.first);
            if (CryptoPQ::kem_decaps(kp.second, enc.first) != enc.second) ok = false;
        }
    });
    std::thread signingThread([&] {
        for (int i = 0; i < 4; ++i) {
            auto kp = CryptoPQ::dsa_keygen();
            auto sig = CryptoPQ::dsa_sign(kp.second, "concurrent", 10);
            if (!CryptoPQ::dsa_verify(kp.first, "concurrent", 10, sig)) ok = false;
        }
    });

    explicitThread.join();
    ordinaryThread.join();
    keygenThread.join();
    signingThread.join();
    EXPECT_TRUE(ok.load());
    EXPECT_EQ(expected, CryptoPQ::kem_encaps_explicit(pub, message));
}

TEST(PqKem_768, DeterministicKeygenReproducible) {
    CryptoPQ::KemKeypairSeed seed{};
    seed[0] = 1; seed[31] = 0x55; seed[63] = 0xff;
    auto [pub1, sk1] = CryptoPQ::kem_keygen_from_seed(seed);
    auto [pub2, sk2] = CryptoPQ::kem_keygen_from_seed(seed);
    EXPECT_EQ(pub1, pub2);
    EXPECT_EQ(sk1, sk2);
}

TEST(PqKem_768, DeterministicKeygenSeedSensitive) {
    CryptoPQ::KemKeypairSeed seed1{}; seed1[0] = 1;
    CryptoPQ::KemKeypairSeed seed2{}; seed2[0] = 2;
    auto [pub1, sk1] = CryptoPQ::kem_keygen_from_seed(seed1);
    auto [pub2, sk2] = CryptoPQ::kem_keygen_from_seed(seed2);
    EXPECT_NE(pub1, pub2);
}

TEST(PqKem_768, DecapsOnGarbageCiphertextDoesNotThrow) {
    // FIPS 203 implicit rejection: malformed ct must yield a pseudorandom
    // ss, not an error. The wallet scan path relies on this — failure must
    // surface via the AEAD tag check, not via an exception here.
    auto [pub, sk] = CryptoPQ::kem_keygen();
    CryptoPQ::KemCiphertext garbage{};
    for (std::size_t i = 0; i < garbage.size(); ++i) {
        garbage[i] = static_cast<uint8_t>(i & 0xff);
    }
    EXPECT_NO_THROW({ (void)CryptoPQ::kem_decaps(sk, garbage); });
}

// ===========================================================================
// ML-DSA-65
// ===========================================================================

TEST(PqDsa_65, SignVerifyRoundTrip) {
    auto [pub, sk] = CryptoPQ::dsa_keygen();
    const char* msg = "the quick brown fox jumps over the lazy dog";
    auto sig = CryptoPQ::dsa_sign(sk, msg, std::strlen(msg));
    EXPECT_TRUE(CryptoPQ::dsa_verify(pub, msg, std::strlen(msg), sig));
}

TEST(PqDsa_65, DeterministicKeygenReproducible) {
    CryptoPQ::DsaKeypairSeed seed{};
    seed[0] = 7; seed[15] = 0x33; seed[31] = 0xab;
    auto [pub1, sk1] = CryptoPQ::dsa_keygen_from_seed(seed);
    auto [pub2, sk2] = CryptoPQ::dsa_keygen_from_seed(seed);
    EXPECT_EQ(pub1, pub2);
    EXPECT_EQ(sk1, sk2);
}

TEST(PqDsa_65, DeterministicKeygenSeedSensitive) {
    CryptoPQ::DsaKeypairSeed s1{}; s1[0] = 1;
    CryptoPQ::DsaKeypairSeed s2{}; s2[0] = 2;
    auto [pub1, sk1] = CryptoPQ::dsa_keygen_from_seed(s1);
    auto [pub2, sk2] = CryptoPQ::dsa_keygen_from_seed(s2);
    EXPECT_NE(pub1, pub2);
}

TEST(PqDsa_65, TamperedSignatureRejected) {
    auto [pub, sk] = CryptoPQ::dsa_keygen();
    const char* msg = "test";
    auto sig = CryptoPQ::dsa_sign(sk, msg, 4);
    sig[100] ^= 0x01;
    EXPECT_FALSE(CryptoPQ::dsa_verify(pub, msg, 4, sig));
}

TEST(PqDsa_65, TamperedMessageRejected) {
    auto [pub, sk] = CryptoPQ::dsa_keygen();
    auto sig = CryptoPQ::dsa_sign(sk, "test", 4);
    EXPECT_TRUE(CryptoPQ::dsa_verify(pub, "test", 4, sig));
    EXPECT_FALSE(CryptoPQ::dsa_verify(pub, "tesT", 4, sig));
}

TEST(PqDsa_65, WrongKeyRejected) {
    auto [pub1, sk1] = CryptoPQ::dsa_keygen();
    auto [pub2, sk2] = CryptoPQ::dsa_keygen();
    const char* msg = "test";
    auto sig = CryptoPQ::dsa_sign(sk1, msg, 4);
    EXPECT_TRUE(CryptoPQ::dsa_verify(pub1, msg, 4, sig));
    EXPECT_FALSE(CryptoPQ::dsa_verify(pub2, msg, 4, sig));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
