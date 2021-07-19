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

#include "table/block_fetcher.h"

#include <cinttypes>
#include <string>

#include "logging/logging.h"
#include "memory/memory_allocator.h"
#include "monitoring/perf_context_imp.h"
#include "rocksdb/env.h"
#include "table/block_based/block.h"
#include "table/block_based/block_based_table_reader.h"
#include "table/block_based/block_decryptor.h"
#include "table/format.h"
#include "table/persistent_cache_helper.h"
#include "util/coding.h"
#include "util/compression.h"
#include "util/crc32c.h"
#include "util/stop_watch.h"
#include "util/string_util.h"
#include "util/xxhash.h"

namespace ROCKSDB_NAMESPACE {

// EDG: replacement for the original BlockFetcher::CheckBlockChecksum()
inline void BlockFetcher::Decrypt() {
  status_ = DecryptBlock(*file_->GetKey(), slice_, handle_);
}

inline bool BlockFetcher::TryGetUncompressBlockFromPersistentCache() {
  if (cache_options_.persistent_cache &&
      !cache_options_.persistent_cache->IsCompressed()) {
    Status status = PersistentCacheHelper::LookupUncompressedPage(
        cache_options_, handle_, contents_);
    if (status.ok()) {
      // uncompressed page is found for the block handle
      return true;
    } else {
      // uncompressed page is not found
      if (ioptions_.info_log && !status.IsNotFound()) {
        assert(!status.ok());
        ROCKS_LOG_INFO(ioptions_.info_log,
                       "Error reading from persistent cache. %s",
                       status.ToString().c_str());
      }
    }
  }
  return false;
}

inline bool BlockFetcher::TryGetFromPrefetchBuffer() {
  if (!prefetch_buffer_) return got_from_prefetch_buffer_;

  decltype(auto) read_offsets = prefetch_buffer_->read_offsets();
  const auto fetched_before =
      read_offsets.find(handle_.offset()) != read_offsets.cend();
  if (prefetch_buffer_->TryReadFromCache(
          handle_.offset(),
          static_cast<size_t>(handle_.size()) + kBlockTrailerSize, &slice_,
          for_compaction_)) {
    block_size_ = static_cast<size_t>(handle_.size());
    // EDG: only decrypt if we haven't seen this block already
    if (!fetched_before) Decrypt();

    if (!status_.ok()) return true;
    got_from_prefetch_buffer_ = true;
    used_buf_ = const_cast<char*>(slice_.data());
  }
  return got_from_prefetch_buffer_;
}

inline bool BlockFetcher::TryGetCompressedBlockFromPersistentCache() {
  if (cache_options_.persistent_cache &&
      cache_options_.persistent_cache->IsCompressed()) {
    // lookup uncompressed cache mode p-cache
    std::unique_ptr<char[]> raw_data;
    status_ = PersistentCacheHelper::LookupRawPage(
        cache_options_, handle_, &raw_data, block_size_ + kBlockTrailerSize);
    if (status_.ok()) {
      heap_buf_ = CacheAllocationPtr(raw_data.release());
      used_buf_ = heap_buf_.get();
      slice_ = Slice(heap_buf_.get(), block_size_);
      return true;
    } else if (!status_.IsNotFound() && ioptions_.info_log) {
      assert(!status_.ok());
      ROCKS_LOG_INFO(ioptions_.info_log,
                     "Error reading from persistent cache. %s",
                     status_.ToString().c_str());
    }
  }
  return false;
}

inline void BlockFetcher::PrepareBufferForBlockFromFile() {
  // cache miss read from device
  if (do_uncompress_ &&
      block_size_ + kBlockTrailerSize < kDefaultStackBufferSize) {
    // If we've got a small enough hunk of data, read it in to the
    // trivially allocated stack buffer instead of needing a full malloc()
    used_buf_ = &stack_buf_[0];
  } else if (maybe_compressed_ && !do_uncompress_) {
    compressed_buf_ = AllocateBlock(block_size_ + kBlockTrailerSize,
                                    memory_allocator_compressed_);
    used_buf_ = compressed_buf_.get();
  } else {
    heap_buf_ =
        AllocateBlock(block_size_ + kBlockTrailerSize, memory_allocator_);
    used_buf_ = heap_buf_.get();
  }
}

inline void BlockFetcher::InsertCompressedBlockToPersistentCacheIfNeeded() {
  if (status_.ok() && read_options_.fill_cache &&
      cache_options_.persistent_cache &&
      cache_options_.persistent_cache->IsCompressed()) {
    // insert to raw cache
    PersistentCacheHelper::InsertRawPage(cache_options_, handle_, used_buf_,
                                         block_size_ + kBlockTrailerSize);
  }
}

inline void BlockFetcher::InsertUncompressedBlockToPersistentCacheIfNeeded() {
  if (status_.ok() && !got_from_prefetch_buffer_ && read_options_.fill_cache &&
      cache_options_.persistent_cache &&
      !cache_options_.persistent_cache->IsCompressed()) {
    // insert to uncompressed cache
    PersistentCacheHelper::InsertUncompressedPage(cache_options_, handle_,
                                                  *contents_);
  }
}

inline void BlockFetcher::CopyBufferToHeap() {
  assert(used_buf_ != heap_buf_.get());
  heap_buf_ = AllocateBlock(block_size_ + kBlockTrailerSize, memory_allocator_);
  memcpy(heap_buf_.get(), used_buf_, block_size_ + kBlockTrailerSize);
}

inline void BlockFetcher::GetBlockContents() {
  if (slice_.data() != used_buf_) {
    // the slice content is not the buffer provided
    *contents_ = BlockContents(Slice(slice_.data(), block_size_));
  } else {
    // page can be either uncompressed or compressed, the buffer either stack
    // or heap provided. Refer to https://github.com/facebook/rocksdb/pull/4096
    if (got_from_prefetch_buffer_ || used_buf_ == &stack_buf_[0]) {
      CopyBufferToHeap();
    } else if (used_buf_ == compressed_buf_.get()) {
      if (compression_type_ == kNoCompression &&
          memory_allocator_ != memory_allocator_compressed_) {
        CopyBufferToHeap();
      } else {
        heap_buf_ = std::move(compressed_buf_);
      }
    }
    *contents_ = BlockContents(std::move(heap_buf_), block_size_);
  }
#ifndef NDEBUG
  contents_->is_raw_block = true;
#endif
}

Status BlockFetcher::ReadBlockContents() {
  block_size_ = static_cast<size_t>(handle_.size());

  if (TryGetUncompressBlockFromPersistentCache()) {
    compression_type_ = kNoCompression;
#ifndef NDEBUG
    contents_->is_raw_block = true;
#endif  // NDEBUG
    return Status::OK();
  }
  if (TryGetFromPrefetchBuffer()) {
    if (!status_.ok()) {
      return status_;
    }
  } else if (!TryGetCompressedBlockFromPersistentCache()) {
    PrepareBufferForBlockFromFile();
    Status s;

    {
      PERF_TIMER_GUARD(block_read_time);
      // Actual file read
      status_ = file_->Read(handle_.offset(), block_size_ + kBlockTrailerSize,
                            &slice_, used_buf_, for_compaction_);
    }
    PERF_COUNTER_ADD(block_read_count, 1);

    // TODO: introduce dedicated perf counter for range tombstones
    switch (block_type_) {
      case BlockType::kFilter:
        PERF_COUNTER_ADD(filter_block_read_count, 1);
        break;

      case BlockType::kCompressionDictionary:
        PERF_COUNTER_ADD(compression_dict_block_read_count, 1);
        break;

      case BlockType::kIndex:
        PERF_COUNTER_ADD(index_block_read_count, 1);
        break;

      // Nothing to do here as we don't have counters for the other types.
      default:
        break;
    }

    PERF_COUNTER_ADD(block_read_byte, block_size_ + kBlockTrailerSize);
    if (!status_.ok()) {
      return status_;
    }

    if (slice_.size() != block_size_ + kBlockTrailerSize) {
      return Status::Corruption("truncated block read from " +
                                file_->file_name() + " offset " +
                                ToString(handle_.offset()) + ", expected " +
                                ToString(block_size_ + kBlockTrailerSize) +
                                " bytes, got " + ToString(slice_.size()));
    }

    Decrypt();
    if (status_.ok()) {
      InsertCompressedBlockToPersistentCacheIfNeeded();
    } else {
      return status_;
    }
  }

  PERF_TIMER_GUARD(block_decompress_time);

  compression_type_ = get_block_compression_type(slice_.data(), block_size_);

  if (do_uncompress_ && compression_type_ != kNoCompression) {
    // compressed page, uncompress, update cache
    UncompressionContext context(compression_type_);
    UncompressionInfo info(context, uncompression_dict_, compression_type_);
    status_ = UncompressBlockContents(info, slice_.data(), block_size_,
                                      contents_, footer_.version(), ioptions_,
                                      memory_allocator_);
    compression_type_ = kNoCompression;
  } else {
    GetBlockContents();
  }

  InsertUncompressedBlockToPersistentCacheIfNeeded();

  return status_;
}

}  // namespace ROCKSDB_NAMESPACE
