// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "encrypted_file.h"

#include <rocksdb/slice.h>

#include <cassert>
#include <iostream>

namespace rocksdb::edg {

void EncryptedFile::CreateKey(edgeless::CBuffer nonce) {
  assert(nonce.size() == kDefaultNonceSize);
  key_ = std::make_unique<edgeless::crypto::Key>(GetMasterKey().Derive(nonce));
}

const edgeless::crypto::Key* EncryptedFile::GetKey() const {
  assert(key_);
  return key_.get();
}

void EncryptedWritableFile::CreateKey() {
  nonce_ = std::make_unique<Nonce>();
  edgeless::crypto::RNG::FillPublic(*nonce_);
  EncryptedFile::CreateKey(*nonce_);
}

std::unique_ptr<EncryptedFile::Nonce> EncryptedWritableFile::GetNonce() {
  assert(nonce_);
  return std::move(nonce_);
}

const edgeless::crypto::Key& EncryptedFile::GetMasterKey() {
  static const edgeless::crypto::Key key = [] {
    std::string decoded_key;
    if (Slice(getenv("EROCKSDB_MASTERKEY")).DecodeHex(&decoded_key) &&
        decoded_key.size() == edgeless::crypto::Key::kSizeKey)
      return edgeless::crypto::Key({decoded_key.cbegin(), decoded_key.cend()});
#ifndef NDEBUG
    return edgeless::crypto::Key::GetTestKey();
#endif
    std::cout << "EROCKSDB_MASTERKEY not set or wrong format\n";
    abort();
  }();
  return key;
}
}  // namespace rocksdb::edg
