#include <cstddef>
#include <cstdint>
extern "C" {
#include "crypto/hash-ops.h"
}
#include "randomx.h"
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// Compare the shared-cache wrapper with independent reference caches while
// validators, seed changes and per-thread VM destruction run concurrently.
int main(int argc, char** argv)
{
  const bool stress = argc == 2 && std::string(argv[1]) == "--stress";
  if (argc != 1 && !stress) return 2;
  using hash = std::array<char, HASH_SIZE>;
  struct sample { hash seed{}, expected{}; std::string input; };
  std::vector<sample> samples(2);
  samples[0].seed.fill(0x31); samples[1].seed.fill(0x62);
  constexpr char input[] = "Salvium audit RandomX cache synchronization";
  for (auto& value : samples) value.input.assign(input, sizeof(input));
  if (stress) {
    auto decode = [](const std::string& hex) {
      std::string result;
      for (size_t i = 0; i < hex.size(); i += 2)
        result.push_back(static_cast<char>(std::stoul(hex.substr(i, 2), nullptr, 16)));
      return result;
    };
    // Public canonical block hashing blobs exercise epoch transitions and
    // historically observed input patterns against independent reference VMs.
    const std::pair<const char*, const char*> vectors[] = {
      {"3df6c9c28a4b8d36eaf37b1939211467f6349447fb1ed14b88fa3ee415bcc142", "0909e8c895bf060ee292a561c206eec9e933bba08bc89f74f95d4af0570b454709d6e00ee1119397210e2a7d86998c588d893daaebcaf10e1a0697f94b6984a18ca47d23b7b8fdf4b0327002"},
      {"3df6c9c28a4b8d36eaf37b1939211467f6349447fb1ed14b88fa3ee415bcc142", "0909fec895bf0604c1ef7da3a144ad145476b6a5e61fc1e6771ad2430857265f0ae53524a177f6e522290019d7669e6b5b7f1e739db940a680333944932eda396cd1f14523b924e4a7b7c702"},
      {"3df6c9c28a4b8d36eaf37b1939211467f6349447fb1ed14b88fa3ee415bcc142", "0909e8c995bf06c9714d8674fc130de8f08b09fb77e1687546b249b2a8cecbc52dbdcb30ab4c633cd907006d1758feac26c830074e233cc6c046a472e6f57fecdf50a9b1b52230713acf5309"},
      {"ebad352d1b8477445499db1b9b566124218ebcc04963b5d0c4f13fa3aef25a96", "0d0db1fdd6d606d910460c78dfe8e1f1bb60e67e43ae3f3ee74684d3ee0fe47f5789e192d34fba61460000328f42d7907385fd5084eab918bb3c852290e7ca0d1bd57c6294d02f40c1b23802"},
      {"f29c548eac8bcf28ae4741bf1dcad74ba9e1a43d85efe7d4387b5a1d5ce7a14c", "0d0ddafed6d606f25f2e8143a3bd9e00aab8c5e0c2d954aa8db2660a74f597e81ec9937a78f42c7c048593b91f24ea975415661b0b0720fb6b9c59f3b9bcce9d93d8e9a4278add87fb062702"},
      {"f29c548eac8bcf28ae4741bf1dcad74ba9e1a43d85efe7d4387b5a1d5ce7a14c", "0d0d8fdcdfd606d9b69cc6a90aa28d4bf914c2b4cefc4e9b845016e9c1c4b7e403d794b24a0afe3bad050048bc1b4da97e7717b01fc09a8e7dcb0509bec327e56d1950dacda665b755942602"},
      {"f29c548eac8bcf28ae4741bf1dcad74ba9e1a43d85efe7d4387b5a1d5ce7a14c", "0d0de0dcdfd6063edd255e3e5b474f1040764525b68009185407c2bb79a9e839ea46fb6e5aa71f86040f00525b8c69f5726823d669983066a870c87f4ae9ae0121620c583379acfaf02dbb02"},
      {"f29c548eac8bcf28ae4741bf1dcad74ba9e1a43d85efe7d4387b5a1d5ce7a14c", "0d0de3dcdfd606ee935162dc92bb71570872162075184f5bc45e0ec5aff3bdbb83bb27f87cda8834031600fef75727a8a9c2e3d3f8711f66b6431cb1522e32d488fbf58730806591feb7b202"},
    };
    samples.clear();
    for (const auto& vector : vectors) {
      sample value;
      const auto seed = decode(vector.first);
      std::memcpy(value.seed.data(), seed.data(), value.seed.size());
      value.input = decode(vector.second);
      samples.push_back(std::move(value));
    }
  }
  auto* cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
  if (!cache) return 1;
  auto* vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, cache, nullptr);
  if (!vm) { randomx_release_cache(cache); return 1; }
  for (auto& sample : samples) {
    randomx_init_cache(cache, sample.seed.data(), sample.seed.size());
    randomx_vm_set_cache(vm, cache);
    randomx_calculate_hash(vm, sample.input.data(), sample.input.size(), sample.expected.data());
  }
  randomx_destroy_vm(vm); randomx_release_cache(cache);
  std::atomic<bool> start{false}, failed{false};
  std::vector<std::thread> workers;
  for (unsigned worker = 0; worker < (stress ? 8u : 6u); ++worker) {
    workers.emplace_back([&, worker] {
      while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
      for (unsigned iteration = 0; iteration < (stress ? 4096u : 12u); ++iteration) {
        const auto index = (iteration / (stress ? 512u : 4u) + (worker % 2) * (stress ? 4u : 1u)) % samples.size();
        const auto& sample = samples[index];
        hash result{};
        rx_slow_hash(sample.seed.data(), sample.input.data(), sample.input.size(), result.data());
        if (result != sample.expected || rx_seedheight(2113) != 2048 || rx_seedheight(2112) != 0)
          failed.store(true);
        if (iteration % (stress ? 256u : 3u) == 0) rx_slow_hash_free_state();
      }
      rx_slow_hash_free_state();
    });
  }
  std::thread updater([&] {
    while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
    for (unsigned iteration = 0; iteration < (stress ? 16u : 2u); ++iteration) {
      rx_set_main_seedhash(samples[(iteration % 2) * (stress ? 4u : 1u)].seed.data(), 4);
      std::this_thread::sleep_for(std::chrono::milliseconds(stress ? 500 : 150));
    }
  });
  start.store(true, std::memory_order_release);
  for (auto& worker : workers) worker.join();
  updater.join();
  if (failed.load()) { std::cerr << "RandomX reference mismatch\n"; return 1; }
  std::cout << "AUDIT_RANDOMX_PASS independent reference, concurrent seeds, validators and VM cleanup; hashes="
      << (stress ? 8u : 6u) * (stress ? 4096u : 12u) << "\n";
}
