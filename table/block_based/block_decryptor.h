// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <edgeless/crypto.h>

#include "table/format.h"

namespace rocksdb {

//! Decrypt block in place
inline Status DecryptBlock(const edgeless::crypto::Key& key, Slice& raw,
                           const BlockHandle& handle) {
  const auto block_size = handle.size();
  assert(raw.size() >= block_size + sizeof(BlockTrailer));
  const auto iv = handle.GetEncIv();
  // The ciphertext includes the block contents and BlockTrailer::type
  edgeless::Buffer ciphertext(
      reinterpret_cast<uint8_t*>(const_cast<char*>(raw.data())),
      block_size + sizeof(BlockTrailer::type));
  const auto trailer =
      reinterpret_cast<const BlockTrailer*>(ciphertext.data() + block_size);
  return key.Decrypt(ciphertext, iv, trailer->tag, ciphertext)
             ? Status::OK()
             : Status::Corruption("AES-GCM tag of block is invalid");
}

}  // namespace rocksdb
