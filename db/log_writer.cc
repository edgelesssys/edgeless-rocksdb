// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "db/log_writer.h"

#include <stdint.h>
#include "file/encrypted_file_util.h"
#include "file/writable_file_writer.h"
#include "rocksdb/env.h"
#include "util/coding.h"
#include "util/crc32c.h"

namespace ROCKSDB_NAMESPACE {
namespace log {

Writer::Writer(std::unique_ptr<WritableFileWriter>&& dest, uint64_t log_number,
               bool recycle_log_files, bool manual_flush)
    : dest_(std::move(dest)),
      block_offset_(0),
      log_number_(log_number),
      manual_flush_(manual_flush) {
  for (int i = 0; i <= kMaxRecordType; i++) {
    char t = static_cast<char>(i);
    type_crc_[i] = crc32c::Value(&t, 1);
  }
}

Writer::~Writer() {
  if (dest_) {
    WriteBuffer();
  }
}

Status Writer::WriteBuffer() { return dest_->Flush(); }

Status Writer::Close() {
  Status s;
  if (dest_) {
    s = dest_->Close();
    dest_.reset();
  }
  return s;
}

Status Writer::AddRecord(const Slice& slice) {
  // EDG: is this the first time we're adding a record? If so, we need to
  // generate a key and write the "nonce record" first.
  if (index_ == 0) {
    dest_->CreateKey();
    const auto s = AddRecordInternal(dest_->GetNonce());
    if (!s.ok()) return s;
  }
  return AddRecordInternal(slice);
}

Status Writer::AddRecordInternal(const Slice& slice) {
  const char* ptr = slice.data();
  size_t left = slice.size();

  // Header size varies depending on whether we are recycling or not.
  const int header_size = sizeof(EncHeader);

  // Fragment the record if necessary and emit it.  Note that if slice
  // is empty, we still want to iterate once to emit a single
  // zero-length record
  Status s;
  bool begin = true;
  do {
    const int64_t leftover = kBlockSize - block_offset_;
    assert(leftover >= 0);
    if (leftover < header_size) {
      // Switch to a new block
      if (leftover > 0) {
        // Fill the trailer
        constexpr std::array<char, header_size> nullbytes{};
        s = dest_->Append(
            Slice(nullbytes.data(), static_cast<size_t>(leftover)));
        if (!s.ok()) {
          break;
        }
      }
      block_offset_ = 0;
    }

    // Invariant: we never leave < header_size bytes in a block.
    assert(static_cast<int64_t>(kBlockSize - block_offset_) >= header_size);

    const size_t avail = kBlockSize - block_offset_ - header_size;
    const size_t fragment_length = (left < avail) ? left : avail;

    RecordType type;
    const bool end = (left == fragment_length);
    if (begin && end) {
      type = recycle_log_files_ ? kRecyclableFullType : kFullType;
    } else if (begin) {
      type = recycle_log_files_ ? kRecyclableFirstType : kFirstType;
    } else if (end) {
      type = recycle_log_files_ ? kRecyclableLastType : kLastType;
    } else {
      type = recycle_log_files_ ? kRecyclableMiddleType : kMiddleType;
    }

    s = EmitPhysicalRecord(type, ptr, fragment_length);
    ptr += fragment_length;
    left -= fragment_length;
    begin = false;
  } while (s.ok() && left > 0);

  if (s.ok()) {
    if (!manual_flush_) {
      s = dest_->Flush();
    }
  }

  return s;
}

bool Writer::TEST_BufferIsEmpty() { return dest_->TEST_BufferIsEmpty(); }

Status Writer::EmitPhysicalRecord(RecordType t, const char* ptr, size_t n) {
  assert(n <= 0xffff);  // Must fit in two bytes
  block_offset_ += sizeof(EncHeader) + n;

  EncHeader header;
  header.meta.length = n;
  header.meta.type = t;

  Status s;
  if (!index_) {
    // zero-out the tag
    header.tag.fill(0);
    s = dest_->Append(edg::ToSliceRaw(header));
    if (!s.ok()) return s;
    s = dest_->Append({ptr, n});  // write "nonce record"
  } else {
    std::vector<uint8_t> ciphertext(n);
    decltype(auto) key = dest_->GetKey();
    key->Encrypt({reinterpret_cast<const uint8_t*>(ptr), n},  // plaintext
                 edgeless::ToCBuffer(index_),                 // iv
                 edgeless::ToCBuffer(header.meta),            // aad
                 header.tag, ciphertext);
    s = dest_->Append(edg::ToSliceRaw(header));
    if (!s.ok()) return s;
    s = dest_->Append(edg::ToSlice(ciphertext));
  }
  if (s.ok()) index_++;
  return s;
}

}  // namespace log
}  // namespace ROCKSDB_NAMESPACE
