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
 * Holds a file-specific key derived from a nonce and the master key.
 * The master key is a static member and is generated once on initialization.
 */
class EncryptedFile {
 public:
  static constexpr size_t kDefaultNonceSize = 16;
  using Nonce = std::array<uint8_t, kDefaultNonceSize>;

  /** Derives the file's key from the given nonce and the master key.
   */
  void CreateKey(edgeless::CBuffer nonce);
  const edgeless::crypto::Key* GetKey() const;

 protected:
  std::unique_ptr<edgeless::crypto::Key> key_;
  static const edgeless::crypto::Key& GetMasterKey();
};

class EncryptedWritableFile : public EncryptedFile {
 public:
  /** Generates a nonce and uses it to derive the file's key from the master
   * key.
   */
  void CreateKey();
  /** Gets the nonce via move. Should only be called once, for writing the nonce
   * out to a file.
   */
  std::unique_ptr<Nonce> GetNonce();

 private:
  std::unique_ptr<Nonce> nonce_;
};

}  // namespace rocksdb::edg
