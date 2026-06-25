// C++ shim that hosts the real Widevine CDM (libwidevinecdm.so) via its
// official interface (cdm::ContentDecryptionModule_11 + cdm::Host_11).
//
// We implement cdm::Host_11 (the compiler enforces every pure-virtual, so the
// vtable is correct-by-construction against the vendored Chromium header), load
// the CDM with dlopen, and expose a tiny C API to Rust:
//
//   ch_open(so_path)                       -> open + init the CDM
//   ch_challenge(init_data,len,out,outlen) -> CreateSessionAndGenerateRequest
//                                             → returns the license challenge
//   ch_update(license,len)                 -> UpdateSession (feed the license)
//   ch_decrypt(...)                        -> Decrypt one CENC buffer
//
// No keys are extracted: the CDM keeps its device key sealed and does the
// challenge/decrypt internally. We only drive it through its public ABI.

#include "content_decryption_module.h"

#include <dlfcn.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <string>
#include <vector>
#include <utility>

using namespace cdm;

namespace {

// Heap-backed cdm::Buffer the CDM uses for its outputs.
class HeapBuffer : public Buffer {
 public:
  explicit HeapBuffer(uint32_t cap) : data_(cap), size_(0) {}
  void Destroy() override { delete this; }
  uint32_t Capacity() const override { return static_cast<uint32_t>(data_.size()); }
  uint8_t* Data() override { return data_.data(); }
  void SetSize(uint32_t size) override { size_ = size; }
  uint32_t Size() const override { return size_; }
 private:
  std::vector<uint8_t> data_;
  uint32_t size_;
};

class Host : public Host_11 {
 public:
  ContentDecryptionModule_11* cdm = nullptr;

  // captured state
  bool initialized = false, init_ok = false;
  std::string session_id;
  bool got_message = false;
  std::vector<uint8_t> challenge;
  bool rejected = false;
  std::string error;
  bool keys_changed = false;
  bool resolved = false;
  std::vector<std::pair<int64_t, void*>> timers;

  void fire_timers() {
    auto t = timers;
    timers.clear();
    for (auto& e : t) if (cdm) cdm->TimerExpired(e.second);
  }

  // --- cdm::Host_11 ---
  Buffer* Allocate(uint32_t capacity) override { return new HeapBuffer(capacity); }
  void SetTimer(int64_t delay_ms, void* context) override { timers.push_back({delay_ms, context}); }
  Time GetCurrentWallTime() override {
    using namespace std::chrono;
    return duration<double>(system_clock::now().time_since_epoch()).count();
  }
  void OnInitialized(bool success) override { initialized = true; init_ok = success; }
  void OnResolveKeyStatusPromise(uint32_t, KeyStatus) override { resolved = true; }
  void OnResolveNewSessionPromise(uint32_t, const char* sid, uint32_t n) override {
    session_id.assign(sid, n); resolved = true;
  }
  void OnResolvePromise(uint32_t) override { resolved = true; }
  void OnRejectPromise(uint32_t, Exception, uint32_t, const char* msg, uint32_t n) override {
    rejected = true; if (msg && n) error.assign(msg, n);
  }
  void OnSessionMessage(const char*, uint32_t, MessageType, const char* msg, uint32_t n) override {
    got_message = true; challenge.assign(reinterpret_cast<const uint8_t*>(msg),
                                         reinterpret_cast<const uint8_t*>(msg) + n);
  }
  void OnSessionKeysChange(const char*, uint32_t, bool, const KeyInformation*, uint32_t) override {
    keys_changed = true;
  }
  void OnExpirationChange(const char*, uint32_t, Time) override {}
  void OnSessionClosed(const char*, uint32_t) override {}
  void SendPlatformChallenge(const char*, uint32_t, const char*, uint32_t) override {}
  void EnableOutputProtection(uint32_t) override {}
  void QueryOutputProtectionStatus() override {}
  void OnDeferredInitializationDone(StreamType, Status) override {}
  FileIO* CreateFileIO(FileIOClient*) override { return nullptr; }
  void RequestStorageId(uint32_t version) override { (void)version; }
  void ReportMetrics(MetricName, uint64_t) override {}
};

Host* g_host = nullptr;

void* GetHost(int version, void* /*user_data*/) {
  if (version == Host_11::kVersion) return static_cast<Host_11*>(g_host);
  return nullptr;
}

}  // namespace

extern "C" {

// 0 = success
int ch_open(const char* so_path) {
  void* lib = dlopen(so_path, RTLD_NOW | RTLD_GLOBAL);
  if (!lib) return 1;
  auto init = reinterpret_cast<void (*)()>(dlsym(lib, "InitializeCdmModule_4"));
  auto create = reinterpret_cast<void* (*)(int, const char*, uint32_t, GetCdmHostFunc, void*)>(
      dlsym(lib, "CreateCdmInstance"));
  if (!init || !create) return 2;
  init();
  g_host = new Host();
  const char* ks = "com.widevine.alpha";
  void* inst = create(11, ks, static_cast<uint32_t>(strlen(ks)), GetHost, nullptr);
  if (!inst) return 3;
  g_host->cdm = static_cast<ContentDecryptionModule_11*>(inst);
  g_host->cdm->Initialize(/*allow_distinctive_identifier=*/false,
                          /*allow_persistent_state=*/false,
                          /*use_hw_secure_codecs=*/false);
  for (int i = 0; i < 200 && !g_host->initialized; ++i) g_host->fire_timers();
  return g_host->initialized && g_host->init_ok ? 0 : 4;
}

// init_data = the CENC pssh box. Returns the license challenge in *out (malloc'd).
int ch_challenge(const uint8_t* init_data, uint32_t len, uint8_t** out, uint32_t* out_len) {
  if (!g_host || !g_host->cdm) return 10;
  g_host->got_message = false; g_host->rejected = false; g_host->challenge.clear();
  g_host->cdm->CreateSessionAndGenerateRequest(1, SessionType::kTemporary,
                                               InitDataType::kCenc, init_data, len);
  for (int i = 0; i < 500 && !g_host->got_message && !g_host->rejected; ++i) g_host->fire_timers();
  if (g_host->rejected) return 11;
  if (!g_host->got_message) return 12;
  *out_len = static_cast<uint32_t>(g_host->challenge.size());
  *out = static_cast<uint8_t*>(malloc(*out_len));
  memcpy(*out, g_host->challenge.data(), *out_len);
  return 0;
}

// Feed the license response back into the CDM.
int ch_update(const uint8_t* license, uint32_t len) {
  if (!g_host || !g_host->cdm) return 20;
  g_host->keys_changed = false; g_host->rejected = false;
  g_host->cdm->UpdateSession(2, g_host->session_id.c_str(),
                             static_cast<uint32_t>(g_host->session_id.size()), license, len);
  for (int i = 0; i < 500 && !g_host->keys_changed && !g_host->rejected; ++i) g_host->fire_timers();
  if (g_host->rejected) return 21;
  return g_host->keys_changed ? 0 : 22;
}

// Decrypt one CENC buffer (single-key, key_id from the pssh). Returns cleartext.
// subs = flattened [clear0, cipher0, clear1, cipher1, ...] (u32 each), num_subs pairs.
int ch_decrypt(const uint8_t* data, uint32_t data_size,
               const uint8_t* key_id, uint32_t key_id_size,
               const uint8_t* iv, uint32_t iv_size,
               const uint32_t* subs, uint32_t num_subs,
               uint8_t** out, uint32_t* out_len) {
  if (!g_host || !g_host->cdm) return 30;
  std::vector<SubsampleEntry> subsamples;
  subsamples.reserve(num_subs);
  for (uint32_t i = 0; i < num_subs; ++i) {
    SubsampleEntry e;
    e.clear_bytes = subs[i * 2];
    e.cipher_bytes = subs[i * 2 + 1];
    subsamples.push_back(e);
  }
  InputBuffer_2 in;
  memset(&in, 0, sizeof(in));
  in.data = data; in.data_size = data_size;
  in.encryption_scheme = EncryptionScheme::kCenc;
  in.key_id = key_id; in.key_id_size = key_id_size;
  in.iv = iv; in.iv_size = iv_size;
  in.subsamples = subsamples.empty() ? nullptr : subsamples.data();
  in.num_subsamples = num_subs;

  // DecryptedBlock + a Buffer come from the CDM/host; the CDM fills them.
  class Block : public DecryptedBlock {
   public:
    Buffer* buf = nullptr; int64_t ts = 0;
    void SetDecryptedBuffer(Buffer* b) override { buf = b; }
    Buffer* DecryptedBuffer() override { return buf; }
    void SetTimestamp(int64_t t) override { ts = t; }
    int64_t Timestamp() const override { return ts; }
  } block;

  Status s = g_host->cdm->Decrypt(in, &block);
  if (s != Status::kSuccess) return 31 + static_cast<int>(s);
  Buffer* b = block.DecryptedBuffer();
  if (!b) return 40;
  *out_len = b->Size();
  *out = static_cast<uint8_t*>(malloc(*out_len));
  memcpy(*out, b->Data(), *out_len);
  b->Destroy();
  return 0;
}

void ch_free(uint8_t* p) { free(p); }

}  // extern "C"
