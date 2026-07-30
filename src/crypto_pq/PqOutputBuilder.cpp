// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Discrete is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Discrete is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Discrete.  If not, see <http://www.gnu.org/licenses/>.

#include "PqOutputBuilder.h"

#include <array>
#include <cstring>
#include <stdexcept>

#include "PqAead.h"
#include "PqRandom.h"
#include "PqScan.h"
#include "Common/SecureMemory.h"

namespace CryptoPQ {

namespace {

// aad = out_context (32) || LE64(amount) — binds the plaintext amount to the
// AEAD so any tampering of the on-chain amount makes the recipient's decrypt
// fail (spec §6.5 / §7).
std::array<uint8_t, 40> makeAad(const Hash256& outContext, uint64_t amount) {
  std::array<uint8_t, 40> aad{};
  std::memcpy(aad.data(), outContext.data(), 32);
  for (int i = 0; i < 8; ++i) {
    aad[32 + i] = static_cast<uint8_t>((amount >> (8 * i)) & 0xFF);
  }
  return aad;
}

}  // namespace

PqBuiltOutput buildPqOutput(const KemCiphertext& kemCt,
                            const KemShared& ss,
                            const DsaPublicKey& recipientSpendPub,
                            const Hash256& inputsHash,
                            uint32_t outputIndex,
                            uint64_t amount,
                            const Rho& rho,
                            uint64_t subaddrIndexT) {
  PqBuiltOutput out;
  out.kemCt = kemCt;
  out.rho = rho;

  out.outContext = outContext(inputsHash, kemCt, outputIndex);

  Hash256 aeadKey = deriveAeadKey(ss, out.outContext);
  AeadNonce nonce{};  // 12 zero bytes — safe, aead key is unique per output
  std::array<uint8_t, 40> aad = makeAad(out.outContext, amount);

  // Plaintext: rho (32 bytes) || LE64(T) (8 bytes) = 40 bytes. Unlike v1, T is
  // NOT bound into outContext (via the key) anymore — it travels only here,
  // inside the AEAD-protected payload, so a tampered T still breaks the tag
  // (the whole 40-byte plaintext is authenticated) but the receiver no longer
  // needs to know T in advance to decrypt.
  std::array<uint8_t, 40> plaintext{};
  std::memcpy(plaintext.data(), rho.data(), 32);
  for (int i = 0; i < 8; ++i)
    plaintext[32 + i] = static_cast<uint8_t>((subaddrIndexT >> (8 * i)) & 0xFF);

  out.encPayload = aead_encrypt(aeadKey, nonce,
                                aad.data(), aad.size(),
                                plaintext.data(), plaintext.size());

  // Ownership binding: the recipient's LONG-TERM spend key, not a per-output key.
  out.spendCommit = spendCommit(recipientSpendPub, rho);
  return out;
}

PqBuiltOutput buildPqOutput(const KemPublicKey& recipientViewPub,
                            const DsaPublicKey& recipientSpendPub,
                            const Hash256& inputsHash,
                            uint32_t outputIndex,
                            uint64_t amount,
                            uint64_t subaddrIndexT) {
  auto encapsulation = kem_encaps(recipientViewPub);
  Tools::SecretLock sharedLock(encapsulation.second.data(), encapsulation.second.size());

  Rho rho{};
  secure_random_bytes(rho.data(), rho.size());
  PqBuiltOutput output = buildPqOutput(
      encapsulation.first, encapsulation.second, recipientSpendPub,
      inputsHash, outputIndex, amount, rho, subaddrIndexT);

  // Sender self-check is exactly the receiver scan predicate after shared-secret
  // recovery: out_context, amount-bound AEAD, rho, and spend commitment. T is no
  // longer an input to that predicate (it's read back from the payload), so
  // confirm it round-tripped to the value we actually encoded.
  PqScanOutput scan;
  scan.outputIndex = outputIndex;
  scan.amount = amount;
  scan.kemCt = output.kemCt;
  scan.encPayload = output.encPayload;
  scan.spendCommit = output.spendCommit;
  auto selfCheck = scanPqOutputWithSharedSecret(
      encapsulation.second, recipientSpendPub, inputsHash, scan);
  if (!selfCheck || selfCheck->subaddrIndexT != subaddrIndexT) {
    throw std::runtime_error("buildPqOutput: sender self-check failed");
  }
  return output;
}

}  // namespace CryptoPQ
