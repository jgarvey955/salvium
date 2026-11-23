#pragma once

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <boost/multiprecision/cpp_int.hpp>

namespace cryptonote { namespace historical_audit {
inline uint64_t checked_amount_sum(uint64_t a, uint64_t b)
{
  if (b > std::numeric_limits<uint64_t>::max() - a)
    throw std::runtime_error("Historical amount sum overflow");
  return a + b;
}

inline uint64_t checked_locked_balance(uint64_t previous, uint64_t matured, uint64_t deposited)
{
  if (matured > previous)
    throw std::runtime_error("Historical stake principal exceeds the locked balance");
  return checked_amount_sum(previous - matured, deposited);
}

inline uint64_t checked_amount_fraction(uint64_t amount, uint64_t numerator, uint64_t denominator)
{
  if (!denominator) throw std::runtime_error("Historical amount division by zero");
  const boost::multiprecision::uint128_t value =
      boost::multiprecision::uint128_t(amount) * numerator / denominator;
  if (value > std::numeric_limits<uint64_t>::max())
    throw std::runtime_error("Historical amount fraction overflow");
  return value.convert_to<uint64_t>();
}
inline uint64_t checked_penalized_reward(uint64_t base, uint64_t median, uint64_t weight)
{
  using boost::multiprecision::uint256_t;
  if (!median || uint256_t(weight) > uint256_t(median) * 2)
    throw std::runtime_error("Invalid historical reward weight");
  if (weight <= median) return base;
  const uint256_t reward = uint256_t(base) * (uint256_t(median) * 2 - weight) * weight /
      median / median;
  return reward.convert_to<uint64_t>();
}
} }
