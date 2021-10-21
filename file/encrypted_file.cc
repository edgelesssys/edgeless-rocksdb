// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "encrypted_file.h"

#include <cassert>
#include <iostream>

#include "file/file_id.h"
#include "file/filename.h"
#include "rocksdb/slice.h"

using namespace edgeless;
using namespace std;

namespace rocksdb::edg {

EncryptedFile::EncryptedFile(const string& file_path) noexcept
    : unique_id_(FileIDFromPath(file_path)) {}

void EncryptedFile::CreateKey(CBuffer nonce) {
  assert(nonce.size() == kDefaultNonceSize);

#ifdef NDEBUG
  // We only throw in release mode, because some RocksDB unit tests manually
  // create files without unique IDs
  if (!unique_id_.has_value())
    throw crypto::Error("Cannot create key for file without unique ID");
#endif

  // Use -1 if we don't have an actual unique ID (only to satisfy tests)
  const auto unique_id = unique_id_.value_or(-1);
  key_.emplace(GetMasterKey().Derive(nonce, ToCBuffer(unique_id)));
}

const optional<crypto::Key>& EncryptedFile::GetKey() const { return key_; }

void EncryptedWritableFile::CreateKey() {
  nonce_.emplace();  // create nonce object
  crypto::RNG::FillPublic(*nonce_);
  EncryptedFile::CreateKey(*nonce_);
}

Slice EncryptedWritableFile::GetNonce() {
  assert(nonce_.has_value());
  return {reinterpret_cast<const char*>(nonce_->data()), nonce_->size()};
}

const crypto::Key& EncryptedFile::GetMasterKey() {
  static const crypto::Key key = [] {
    string decoded_key;
    if (Slice(getenv("EROCKSDB_MASTERKEY")).DecodeHex(&decoded_key) &&
        decoded_key.size() == crypto::Key::kSizeKey)
      return crypto::Key({decoded_key.cbegin(), decoded_key.cend()});
#ifndef NDEBUG
    return crypto::Key::GetTestKey();
#endif
    cout << "EROCKSDB_MASTERKEY not set or wrong format\n";
    abort();
  }();
  return key;
}
}  // namespace rocksdb::edg
