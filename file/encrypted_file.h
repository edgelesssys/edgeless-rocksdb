// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <edgeless/crypto.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>

#include "rocksdb/slice.h"

namespace rocksdb::edg {

/** Base class for encrypted files.
 *
 * Holds a file-specific key which is derived from the master key, a random
 * nonce, the file's unique ID, using HKDF. The master key is a static member
 * and is generated once on initialization.
 */
class EncryptedFile {
 public:
  static constexpr size_t kDefaultNonceSize = 16;

  // Obtains the file's uniqe ID from the file path
  EncryptedFile(const std::string& file_path) noexcept;
  EncryptedFile(EncryptedFile&&) = default;

  // Derives the file's key from the given nonce.
  void CreateKey(edgeless::CBuffer nonce);
  const std::optional<edgeless::crypto::Key>& GetKey() const;

 protected:
  std::optional<edgeless::crypto::Key> key_;
  std::optional<uint64_t> unique_id_;
  static const edgeless::crypto::Key& GetMasterKey();
};

class EncryptedWritableFile : public EncryptedFile {
 public:
  using EncryptedFile::EncryptedFile;

  // Generates a new random nonce and derives a key.
  void CreateKey();
  // Get a Slice for the nonce
  Slice GetNonce();

 private:
  std::optional<std::array<uint8_t, kDefaultNonceSize>> nonce_;
};

}  // namespace rocksdb::edg
