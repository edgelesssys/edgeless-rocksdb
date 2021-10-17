// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <edgeless/crypto.h>

#include <array>
#include <memory>

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
  using Nonce = std::array<uint8_t, kDefaultNonceSize>;

  // Obtains the file's uniqe ID from the file path
  EncryptedFile(const std::string& file_path) noexcept;
  EncryptedFile(EncryptedFile&&) = default;

  // Derives the file's key from the given nonce.
  void CreateKey(edgeless::CBuffer nonce);
  const edgeless::crypto::Key* GetKey() const;

 protected:
  std::unique_ptr<edgeless::crypto::Key> key_;
  std::optional<uint64_t> unique_id_;
  static const edgeless::crypto::Key& GetMasterKey();
};

class EncryptedWritableFile : public EncryptedFile {
 public:
  using EncryptedFile::EncryptedFile;

  // Generates a new random nonce and derives a key.
  void CreateKey();
  // Gets the nonce via move. Should only be called once, for writing the nonce
  // out to a file.
  std::unique_ptr<Nonce> GetNonce();

 private:
  std::unique_ptr<Nonce> nonce_;
};

}  // namespace rocksdb::edg
