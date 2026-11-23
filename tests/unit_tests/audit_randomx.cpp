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
#include <thread>
#include <vector>

// Compare the shared-cache wrapper with independent reference caches while
// validators, seed changes and per-thread VM destruction run concurrently.
int main()
{
  using hash = std::array<char, HASH_SIZE>;
  std::array<hash, 2> seeds{}, expected{};
  seeds[0].fill(0x31); seeds[1].fill(0x62);
  constexpr char input[] = "Salvium audit RandomX cache synchronization";
  auto* cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
  if (!cache) return 1;
  auto* vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, cache, nullptr);
  if (!vm) { randomx_release_cache(cache); return 1; }
  for (size_t i = 0; i < seeds.size(); ++i) {
    randomx_init_cache(cache, seeds[i].data(), seeds[i].size());
    randomx_vm_set_cache(vm, cache);
    randomx_calculate_hash(vm, input, sizeof(input), expected[i].data());
  }
  randomx_destroy_vm(vm); randomx_release_cache(cache);
  std::atomic<bool> start{false}, failed{false};
  std::vector<std::thread> workers;
  for (unsigned worker = 0; worker < 6; ++worker) {
    workers.emplace_back([&, worker] {
      while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
      for (unsigned iteration = 0; iteration < 12; ++iteration) {
        const auto index = (iteration / 4 + worker % 2) % seeds.size();
        hash result{};
        rx_slow_hash(seeds[index].data(), input, sizeof(input), result.data());
        if (result != expected[index] || rx_seedheight(2113) != 2048 || rx_seedheight(2112) != 0)
          failed.store(true);
        if (iteration % 3 == 0) rx_slow_hash_free_state();
      }
      rx_slow_hash_free_state();
    });
  }
  std::thread updater([&] {
    while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
    for (const auto& seed : seeds) {
      rx_set_main_seedhash(seed.data(), 4);
      std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
  });
  start.store(true, std::memory_order_release);
  for (auto& worker : workers) worker.join();
  updater.join();
  if (failed.load()) { std::cerr << "RandomX reference mismatch\n"; return 1; }
  std::cout << "AUDIT_RANDOMX_PASS independent reference, concurrent seeds, validators and VM cleanup\n";
}
