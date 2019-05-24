//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once
#include <string>
#include <db/dbformat.h>
#include "db/merge_context.h"
#include "db/read_callback.h"
#include "rocksdb/env.h"
#include "rocksdb/statistics.h"
#include "rocksdb/types.h"
#include "table/block.h"

namespace rocksdb {
class MergeContext;
class PinnedIteratorsManager;

// Data structure for accumulating statistics during a point lookup. At the
// end of the point lookup, the corresponding ticker stats are updated. This
// avoids the overhead of frequent ticker stats updates
struct GetContextStats {
  uint64_t num_cache_hit = 0;
  uint64_t num_cache_index_hit = 0;
  uint64_t num_cache_data_hit = 0;
  uint64_t num_cache_filter_hit = 0;
  uint64_t num_cache_compression_dict_hit = 0;
  uint64_t num_cache_index_miss = 0;
  uint64_t num_cache_filter_miss = 0;
  uint64_t num_cache_data_miss = 0;
  uint64_t num_cache_compression_dict_miss = 0;
  uint64_t num_cache_bytes_read = 0;
  uint64_t num_cache_miss = 0;
  uint64_t num_cache_add = 0;
  uint64_t num_cache_bytes_write = 0;
  uint64_t num_cache_index_add = 0;
  uint64_t num_cache_index_bytes_insert = 0;
  uint64_t num_cache_data_add = 0;
  uint64_t num_cache_data_bytes_insert = 0;
  uint64_t num_cache_filter_add = 0;
  uint64_t num_cache_filter_bytes_insert = 0;
  uint64_t num_cache_compression_dict_add = 0;
  uint64_t num_cache_compression_dict_bytes_insert = 0;
};

// A class to hold context about a point lookup, such as pointer to value
// slice, key, merge context etc, as well as the current state of the
// lookup. Any user using GetContext to track the lookup result must call
// SaveValue() whenever the internal key is found. This can happen
// repeatedly in case of merge operands. In case the key may exist with
// high probability, but IO is required to confirm and the user doesn't allow
// it, MarkKeyMayExist() must be called instead of SaveValue().
class GetContext {
 public:
  // Current state of the point lookup. All except kNotFound and kMerge are
  // terminal states
  enum GetState {
    kNotFound,
    kFound,
    kDeleted,
    kCorrupt,
    kMerge,  // saver contains the current merge result (the operands)
    kBlobIndex,
  };
  GetContextStats get_context_stats_;

  // Constructor
  // @param value_found If non-nullptr, set to false if key may be present
  //                    but we can't be certain because we cannot do IO
  // @param max_covering_tombstone_seq Pointer to highest sequence number of
  //                    range deletion covering the key. When an internal key
  //                    is found with smaller sequence number, the lookup
  //                    terminates
  // @param seq If non-nullptr, the sequence number of the found key will be
  //            saved here
  // @param callback Pointer to ReadCallback to perform additional checks
  //                 for visibility of a key
  // @param is_blob_index If non-nullptr, will be used to indicate if a found
  //                      key is of type blob index
  GetContext(const Comparator* ucmp, const MergeOperator* merge_operator,
             Logger* logger, Statistics* statistics, GetState init_state,
             const Slice& user_key, PinnableSlice* value, bool* value_found,
             MergeContext* merge_context,
             SequenceNumber* max_covering_tombstone_seq, Env* env,
             SequenceNumber* seq = nullptr,
             PinnedIteratorsManager* _pinned_iters_mgr = nullptr,
             ReadCallback* callback = nullptr, bool* is_blob_index = nullptr);

  GetContext() = default;

  // This can be called to indicate that a key may be present, but cannot be
  // confirmed due to IO not allowed
  void MarkKeyMayExist();

  // Records this key, value, and any meta-data (such as sequence number and
  // state) into this GetContext.
  //
  // If the parsed_key matches the user key that we are looking for, sets
  // matched to true.
  //
  // Returns True if more keys need to be read (due to merges) or
  //         False if the complete value has been found.
  bool SaveValue(const ParsedInternalKey& parsed_key, const Slice& value,
                 bool* matched, Cleanable* value_pinner = nullptr);

  // Simplified version of the previous function. Should only be used when we
  // know that the operation is a Put.
  void SaveValue(const Slice& value, SequenceNumber seq);

  GetState State() const { return state_; }

  SequenceNumber* max_covering_tombstone_seq() {
    return max_covering_tombstone_seq_;
  }

  PinnedIteratorsManager* pinned_iters_mgr() { return pinned_iters_mgr_; }

  // If a non-null string is passed, all the SaveValue calls will be
  // logged into the string. The operations can then be replayed on
  // another GetContext with replayGetContextLog.
  void SetReplayLog(std::string* replay_log) { replay_log_ = replay_log; }

  // Do we need to fetch the SequenceNumber for this key?
  bool NeedToReadSequence() const { return (seq_ != nullptr); }

  bool sample() const { return sample_; }

  bool CheckCallback(SequenceNumber seq) {
    if (callback_) {
      return callback_->IsVisible(seq);
    }
    return true;
  }

  void ReportCounters();

 private:
  const Comparator* ucmp_;
  const MergeOperator* merge_operator_;
  // the merge operations encountered;
  Logger* logger_;
  Statistics* statistics_;

  GetState state_;
  Slice user_key_;
  PinnableSlice* pinnable_val_;
  bool* value_found_;  // Is value set correctly? Used by KeyMayExist
  MergeContext* merge_context_;
  SequenceNumber* max_covering_tombstone_seq_;
  Env* env_;
  // If a key is found, seq_ will be set to the SequenceNumber of most recent
  // write to the key or kMaxSequenceNumber if unknown
  SequenceNumber* seq_;
  std::string* replay_log_;
  // Used to temporarily pin blocks when state_ == GetContext::kMerge
  PinnedIteratorsManager* pinned_iters_mgr_;
  ReadCallback* callback_;
  bool sample_;
  bool* is_blob_index_;
};

// Call this to replay a log and bring the get_context up to date. The replay
// log must have been created by another GetContext object, whose replay log
// must have been set by calling GetContext::SetReplayLog().
void replayGetContextLog(const Slice& replay_log, const Slice& user_key,
                         GetContext* get_context,
                         Cleanable* value_pinner = nullptr);

}  // namespace rocksdb
