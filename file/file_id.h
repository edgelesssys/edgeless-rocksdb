// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <optional>
#include <filesystem>

#include "file/filename.h"

namespace rocksdb::edg {

// Parse unique ID from file path
inline std::optional<uint64_t> FileIDFromPath(const std::string& file_path) {
  // Parse the file's unique ID from the path. RocksDB generates file paths
  // using the functions in filename.h

  // TODO: this could be optimized by maintaining a global mapping from file
  // path to unique ID in filename.cc
  const auto path = std::filesystem::path(file_path);
  if (!path.has_filename()) return {};
  const auto file_name = path.filename().generic_string();

  FileType type;
  WalFileType log_type;
  uint64_t unique_id;
  if (!ParseFileName(file_name, &unique_id, &type, &log_type)) return {};
  return unique_id;
}
}  // namespace rocksdb