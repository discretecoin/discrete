// Copyright (c) 2026, The Karbo developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

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

  out.outContext = outContext(inputsHash, kemCt, outputIndex, subaddrIndexT);

  Hash256 aeadKey = deriveAeadKey(ss, out.outContext);
  AeadNonce nonce{};  // 12 zero bytes — safe, aead key is unique per output
  std::array<uint8_t, 40> aad = makeAad(out.outContext, amount);

  // Plaintext: rho (32 bytes) || LE64(T) (8 bytes) = 40 bytes.
  // T is also bound into outContext (via the key), so a tampered T
  // in the payload cannot be re-encrypted to pass the AEAD tag check.
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
  // recovery: out_context/T, amount-bound AEAD, rho, and spend commitment.
  PqScanOutput scan;
  scan.outputIndex = outputIndex;
  scan.amount = amount;
  scan.kemCt = output.kemCt;
  scan.encPayload = output.encPayload;
  scan.spendCommit = output.spendCommit;
  if (!scanPqOutputWithSharedSecret(
          encapsulation.second, recipientSpendPub, inputsHash, scan,
          subaddrIndexT)) {
    throw std::runtime_error("buildPqOutput: sender self-check failed");
  }
  return output;
}

}  // namespace CryptoPQ
