// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "encrypted_file.h"

#include <rocksdb/slice.h>

#include <cassert>
#include <filesystem>
#include <iostream>

#include "file/filename.h"

using namespace edgeless;

namespace rocksdb::edg {

EncryptedFile::EncryptedFile(const std::string& file_path) noexcept {
  // Parse the file's unique ID from the path. RocksDB generates file paths
  // using the functions in filename.h

  // TODO: this could be optimized by maintaining a global mapping from file
  // path to unique ID in filename.cc
  const auto path = std::filesystem::path(file_path);
  if (!path.has_filename()) return;
  const auto file_name = path.filename().generic_string();

  FileType type;
  WalFileType log_type;
  uint64_t unique_id;
  if (!ParseFileName(file_name, &unique_id, &type, &log_type)) return;
  unique_id_ = unique_id;
}

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
  key_ = std::make_unique<crypto::Key>(
      GetMasterKey().Derive(nonce, ToCBuffer(unique_id)));
}

const crypto::Key* EncryptedFile::GetKey() const {
  assert(key_);
  return key_.get();
}

void EncryptedWritableFile::CreateKey() {
  nonce_ = std::make_unique<Nonce>();
  crypto::RNG::FillPublic(*nonce_);
  EncryptedFile::CreateKey(*nonce_);
}

std::unique_ptr<EncryptedFile::Nonce> EncryptedWritableFile::GetNonce() {
  assert(nonce_);
  return std::move(nonce_);
}

const crypto::Key& EncryptedFile::GetMasterKey() {
  static const crypto::Key key = [] {
    std::string decoded_key;
    if (Slice(getenv("EROCKSDB_MASTERKEY")).DecodeHex(&decoded_key) &&
        decoded_key.size() == crypto::Key::kSizeKey)
      return crypto::Key({decoded_key.cbegin(), decoded_key.cend()});
#ifndef NDEBUG
    return crypto::Key::GetTestKey();
#endif
    std::cout << "EROCKSDB_MASTERKEY not set or wrong format\n";
    abort();
  }();
  return key;
}
}  // namespace rocksdb::edg
