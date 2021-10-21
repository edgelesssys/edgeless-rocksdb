// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "encrypted_file_util.h"

#include <limits>
#include <string>

using namespace std;
using namespace edgeless;

namespace rocksdb::edg {

#pragma pack(push, 1)
struct EncRecordHeader {
  crypto::Tag tag;
  uint32_t size;
};
#pragma pack(pop)

// Writes an encrypted record to the given file. Takes care of all formatting,
// like writing a nonce.
bool WriteEncRecord(WritableFileWriter& file, const Slice& record,
                    const uint64_t iv) {
  if (record.size() > numeric_limits<decltype(EncRecordHeader::size)>::max())
    return false;

  decltype(auto) key = file.GetKey();
  // do we have a key yet?
  if (!key.has_value()) {
    assert(!file.GetFileSize());
    file.CreateKey();
    // write nonce to beginning of file
    if (!file.Append(file.GetNonce()).ok()) return false;
  }

  vector<uint8_t> ct(record.size());
  EncRecordHeader header{.size = static_cast<uint32_t>(record.size())};
  key->Encrypt(
      CBuffer{reinterpret_cast<const uint8_t*>(record.data()), record.size()},
      ToCBuffer(iv), header.tag, ct);
  if (!file.Append(ToSliceRaw(header)).ok()) return false;
  if (!file.Append(ToSlice(ct)).ok()) return false;
  return true;
}

optional<string> ReadEncRecord(SequentialFileReader& file, const uint64_t iv) {
  decltype(auto) key = file.GetKey();
  // do we have a key yet?
  if (!key.has_value()) {
    // read nonce from beginnig of file
    array<uint8_t, EncryptedFile::kDefaultNonceSize> nonce;
    Slice slice;
    if (!file.Read(sizeof(nonce), &slice, reinterpret_cast<char*>(nonce.data()))
             .ok())
      return {};
    file.CreateKey(nonce);
  }
  EncRecordHeader header;
  Slice slice;
  if (!file.Read(sizeof(header), &slice, reinterpret_cast<char*>(&header)).ok())
    return {};

  string record;
  // the size field in the header is untrusted, we're thus being cautious...
  try {
    record.resize(header.size);
  } catch (const bad_alloc&) {
    return {};
  }
  if (!file.Read(header.size, &slice, record.data()).ok()) return {};

  Buffer buf{reinterpret_cast<uint8_t*>(record.data()), record.size()};
  if (!key->Decrypt(buf, ToCBuffer(iv), header.tag, buf)) return {};
  return record;
}

}  // namespace rocksdb
