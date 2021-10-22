// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <edgeless/buffer.h>

#include <cstdint>
#include <optional>
#include <string>

#include "file/sequence_file_reader.h"
#include "file/writable_file_writer.h"

namespace rocksdb::edg {

template <typename T>
Slice ToSliceRaw(T& o) {
  return {reinterpret_cast<const char*>(&o), sizeof(o)};
}

inline Slice ToSlice(const edgeless::CBuffer& b) {
  return {reinterpret_cast<const char*>(b.data()), b.size()};
}

// Writes an encrypted record to the given file. Takes care of all formatting,
// like writing a nonce.
bool WriteEncRecord(WritableFileWriter& file, const Slice& record,
                    const uint64_t iv);

// Reads an encrypted record from the given file. Takes care of deriving the key
// if necessary.
std::optional<std::string> ReadEncRecord(SequentialFileReader& file,
                                         const uint64_t iv);

}  // namespace rocksdb::edg
