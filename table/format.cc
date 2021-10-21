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

#include "table/format.h"

#include <cinttypes>
#include <string>

#include "block_fetcher.h"
#include "file/random_access_file_reader.h"
#include "logging/logging.h"
#include "memory/memory_allocator.h"
#include "monitoring/perf_context_imp.h"
#include "monitoring/statistics.h"
#include "rocksdb/env.h"
#include "table/block_based/block.h"
#include "table/block_based/block_based_table_reader.h"
#include "table/persistent_cache_helper.h"
#include "util/coding.h"
#include "util/compression.h"
#include "util/crc32c.h"
#include "util/stop_watch.h"
#include "util/string_util.h"

using namespace edgeless;

namespace ROCKSDB_NAMESPACE {

// EDG: copied here for linking compatibility
extern const uint64_t kPlainTableMagicNumber = 0x8242229663bf9564ull;
extern const uint64_t kLegacyPlainTableMagicNumber = 0x4f3418eb7a8f13b8ull;

bool ShouldReportDetailedTime(Env* env, Statistics* stats) {
  return env != nullptr && stats != nullptr &&
         stats->get_stats_level() > kExceptDetailedTimers;
}

void BlockHandle::EncodeTo(std::string* dst) const {
  // Sanity check that all fields have been set
  assert(offset_ != ~static_cast<uint64_t>(0));
  assert(size_ != ~static_cast<uint64_t>(0));
  PutVarint64Varint64(dst, offset_, size_);
}

Status BlockHandle::DecodeFrom(Slice* input) {
  if (GetVarint64(input, &offset_) && GetVarint64(input, &size_)) {
    return Status::OK();
  } else {
    // reset in case failure after partially decoding
    offset_ = 0;
    size_ = 0;
    return Status::Corruption("bad block handle");
  }
}

Status BlockHandle::DecodeSizeFrom(uint64_t _offset, Slice* input) {
  if (GetVarint64(input, &size_)) {
    offset_ = _offset;
    return Status::OK();
  } else {
    // reset in case failure after partially decoding
    offset_ = 0;
    size_ = 0;
    return Status::Corruption("bad block handle");
  }
}

// Return a string that contains the copy of handle.
std::string BlockHandle::ToString(bool hex) const {
  std::string handle_str;
  EncodeTo(&handle_str);
  if (hex) {
    return Slice(handle_str).ToString(true);
  } else {
    return handle_str;
  }
}

CBuffer BlockHandle::GetEncIv() const {
  return {reinterpret_cast<const uint8_t*>(&offset_), sizeof(offset_)};
}

const BlockHandle BlockHandle::kNullBlockHandle(0, 0);

void IndexValue::EncodeTo(std::string* dst, bool have_first_key,
                          const BlockHandle* previous_handle) const {
  if (previous_handle) {
    assert(handle.offset() == previous_handle->offset() +
                                  previous_handle->size() + kBlockTrailerSize);
    PutVarsignedint64(dst, handle.size() - previous_handle->size());
  } else {
    handle.EncodeTo(dst);
  }
  assert(dst->size() != 0);

  if (have_first_key) {
    PutLengthPrefixedSlice(dst, first_internal_key);
  }
}

Status IndexValue::DecodeFrom(Slice* input, bool have_first_key,
                              const BlockHandle* previous_handle) {
  if (previous_handle) {
    int64_t delta;
    if (!GetVarsignedint64(input, &delta)) {
      return Status::Corruption("bad delta-encoded index value");
    }
    handle = BlockHandle(
        previous_handle->offset() + previous_handle->size() + kBlockTrailerSize,
        previous_handle->size() + delta);
  } else {
    Status s = handle.DecodeFrom(input);
    if (!s.ok()) {
      return s;
    }
  }

  if (!have_first_key) {
    first_internal_key = Slice();
  } else if (!GetLengthPrefixedSlice(input, &first_internal_key)) {
    return Status::Corruption("bad first key in block info");
  }

  return Status::OK();
}

std::string IndexValue::ToString(bool hex, bool have_first_key) const {
  std::string s;
  EncodeTo(&s, have_first_key, nullptr);
  if (hex) {
    return Slice(s).ToString(true);
  } else {
    return s;
  }
}

// EDG: AES-GCM integrity-protected footer format:
//    metaindex handle (varint64 offset, varint64 size)
//    index handle     (varint64 offset, varint64 size)
//    <padding> to make the above a total size of 2 *
//    BlockHandle::kMaxEncodedLength
//    AES-GCM tag for the above (16 bytes)
//    key-derivation nonce      (16 bytes)
//
// We use a fixed IV for the footer to disambiguate it from other blocks in a
// file
void Footer::EncodeTo(std::string* dst, edg::EncryptedWritableFile& file) const {
  auto const target_size = dst->size() + kSize;
  // Write encoded handles
  metaindex_handle_.EncodeTo(dst);
  index_handle_.EncodeTo(dst);
  dst->resize(target_size);

  const auto dst_end = reinterpret_cast<uint8_t*>(dst->data() + dst->size());
  Buffer handles(dst_end - kSize, kSizeHandles);
  // Write AES-GCM tag directly after padding
  Buffer tag(handles.data() + handles.size(), crypto::Key::kSizeTag);
  file.GetKey()->Encrypt(kIv, handles, tag);
  // Write the nonce to the end
  const auto nonce = file.GetNonce();
  std::copy_n(nonce.data(), nonce.size(), tag.data() + tag.size());
}

Status Footer::DecodeFrom(Slice* input, edg::EncryptedFile& file) {
  // EDG: verify footer's tag and parse
  assert(input);
  if (input->size() < kSize)
    return Status::InvalidArgument("Buffer is shorter than footer.");

  CBuffer handles(reinterpret_cast<const uint8_t*>(input->data()),
                  kSizeHandles);
  CBuffer tag(handles.data() + handles.size(), crypto::Key::kSizeTag);
  CBuffer nonce(tag.data() + tag.size(), edg::EncryptedFile::kDefaultNonceSize);
  // Create key from nonce and decrypt
  file.CreateKey(nonce);
  if (!file.GetKey()->Decrypt(kIv, handles, tag))
    return Status::Corruption("Failed to verify footer's tag.");

  // Read-in handles
  const auto result = metaindex_handle_.DecodeFrom(input);
  if (!result.ok()) return result;

  return index_handle_.DecodeFrom(input);
}

std::string Footer::ToString() const {
  std::string result;

  result.append("metaindex handle: " + metaindex_handle_.ToString() + "\n  ");
  result.append("index handle: " + index_handle_.ToString() + "\n  ");

  return result;
}

Status ReadFooterFromFile(RandomAccessFileReader* file,
                          FilePrefetchBuffer* prefetch_buffer,
                          uint64_t file_size, Footer* footer,
                          uint64_t enforce_table_magic_number) {
  if (file_size < Footer::kSize) {
    return Status::Corruption("file is too short (" + ToString(file_size) +
                              " bytes) to be an "
                              "sstable: " +
                              file->file_name());
  }

  char footer_space[Footer::kSize];
  Slice footer_input;
  const size_t read_offset = static_cast<size_t>(file_size - Footer::kSize);
  Status s;
  if (prefetch_buffer == nullptr ||
      !prefetch_buffer->TryReadFromCache(read_offset, Footer::kSize,
                                         &footer_input)) {
    s = file->Read(read_offset, Footer::kSize, &footer_input, footer_space);

    if (!s.ok()) return s;
  }

  // Check that we actually read the whole footer from the file. It may be
  // that size isn't correct.
  if (footer_input.size() < Footer::kSize) {
    return Status::Corruption("file is too short (" + ToString(file_size) +
                              " bytes) to be an "
                              "sstable" +
                              file->file_name());
  }

  return footer->DecodeFrom(&footer_input, *file);
}

Status UncompressBlockContentsForCompressionType(
    const UncompressionInfo& uncompression_info, const char* data, size_t n,
    BlockContents* contents, uint32_t format_version,
    const ImmutableCFOptions& ioptions, MemoryAllocator* allocator) {
  CacheAllocationPtr ubuf;

  assert(uncompression_info.type() != kNoCompression &&
         "Invalid compression type");

  StopWatchNano timer(ioptions.env, ShouldReportDetailedTime(
                                        ioptions.env, ioptions.statistics));
  int decompress_size = 0;
  switch (uncompression_info.type()) {
    case kSnappyCompression: {
      size_t ulength = 0;
      static char snappy_corrupt_msg[] =
          "Snappy not supported or corrupted Snappy compressed block contents";
      if (!Snappy_GetUncompressedLength(data, n, &ulength)) {
        return Status::Corruption(snappy_corrupt_msg);
      }
      ubuf = AllocateBlock(ulength, allocator);
      if (!Snappy_Uncompress(data, n, ubuf.get())) {
        return Status::Corruption(snappy_corrupt_msg);
      }
      *contents = BlockContents(std::move(ubuf), ulength);
      break;
    }
    case kZlibCompression:
      ubuf = Zlib_Uncompress(
          uncompression_info, data, n, &decompress_size,
          GetCompressFormatForVersion(kZlibCompression, format_version),
          allocator);
      if (!ubuf) {
        static char zlib_corrupt_msg[] =
            "Zlib not supported or corrupted Zlib compressed block contents";
        return Status::Corruption(zlib_corrupt_msg);
      }
      *contents = BlockContents(std::move(ubuf), decompress_size);
      break;
    case kBZip2Compression:
      ubuf = BZip2_Uncompress(
          data, n, &decompress_size,
          GetCompressFormatForVersion(kBZip2Compression, format_version),
          allocator);
      if (!ubuf) {
        static char bzip2_corrupt_msg[] =
            "Bzip2 not supported or corrupted Bzip2 compressed block contents";
        return Status::Corruption(bzip2_corrupt_msg);
      }
      *contents = BlockContents(std::move(ubuf), decompress_size);
      break;
    case kLZ4Compression:
      ubuf = LZ4_Uncompress(
          uncompression_info, data, n, &decompress_size,
          GetCompressFormatForVersion(kLZ4Compression, format_version),
          allocator);
      if (!ubuf) {
        static char lz4_corrupt_msg[] =
            "LZ4 not supported or corrupted LZ4 compressed block contents";
        return Status::Corruption(lz4_corrupt_msg);
      }
      *contents = BlockContents(std::move(ubuf), decompress_size);
      break;
    case kLZ4HCCompression:
      ubuf = LZ4_Uncompress(
          uncompression_info, data, n, &decompress_size,
          GetCompressFormatForVersion(kLZ4HCCompression, format_version),
          allocator);
      if (!ubuf) {
        static char lz4hc_corrupt_msg[] =
            "LZ4HC not supported or corrupted LZ4HC compressed block contents";
        return Status::Corruption(lz4hc_corrupt_msg);
      }
      *contents = BlockContents(std::move(ubuf), decompress_size);
      break;
    case kXpressCompression:
      // XPRESS allocates memory internally, thus no support for custom
      // allocator.
      ubuf.reset(XPRESS_Uncompress(data, n, &decompress_size));
      if (!ubuf) {
        static char xpress_corrupt_msg[] =
            "XPRESS not supported or corrupted XPRESS compressed block "
            "contents";
        return Status::Corruption(xpress_corrupt_msg);
      }
      *contents = BlockContents(std::move(ubuf), decompress_size);
      break;
    case kZSTD:
    case kZSTDNotFinalCompression:
      ubuf = ZSTD_Uncompress(uncompression_info, data, n, &decompress_size,
                             allocator);
      if (!ubuf) {
        static char zstd_corrupt_msg[] =
            "ZSTD not supported or corrupted ZSTD compressed block contents";
        return Status::Corruption(zstd_corrupt_msg);
      }
      *contents = BlockContents(std::move(ubuf), decompress_size);
      break;
    default:
      return Status::Corruption("bad block type");
  }

  if (ShouldReportDetailedTime(ioptions.env, ioptions.statistics)) {
    RecordTimeToHistogram(ioptions.statistics, DECOMPRESSION_TIMES_NANOS,
                          timer.ElapsedNanos());
  }
  RecordTimeToHistogram(ioptions.statistics, BYTES_DECOMPRESSED,
                        contents->data.size());
  RecordTick(ioptions.statistics, NUMBER_BLOCK_DECOMPRESSED);

  return Status::OK();
}

//
// The 'data' points to the raw block contents that was read in from file.
// This method allocates a new heap buffer and the raw block
// contents are uncompresed into this buffer. This
// buffer is returned via 'result' and it is upto the caller to
// free this buffer.
// format_version is the block format as defined in include/rocksdb/table.h
Status UncompressBlockContents(const UncompressionInfo& uncompression_info,
                               const char* data, size_t n,
                               BlockContents* contents, uint32_t format_version,
                               const ImmutableCFOptions& ioptions,
                               MemoryAllocator* allocator) {
  assert(data[n] != kNoCompression);
  assert(data[n] == uncompression_info.type());
  return UncompressBlockContentsForCompressionType(uncompression_info, data, n,
                                                   contents, format_version,
                                                   ioptions, allocator);
}

}  // namespace ROCKSDB_NAMESPACE
