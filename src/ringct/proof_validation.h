#pragma once
#include "rctOps.h"
#include <cstring>

namespace rct {
// Reject noncanonical encodings and torsion before doing proof arithmetic.
// Identity is a valid zero-valued remainder commitment, but cannot be a spend key.
inline bool canonical_subgroup_point(const key& point) {
  ge_p3 decoded;
  if (!toPointCheckOrder(&decoded, point.bytes)) return false;
  key encoded;
  ge_p3_tobytes(encoded.bytes, &decoded);
  return encoded == point;
}
inline bool canonical_spend_point(const key& point) {
  return !(point == identity()) && canonical_subgroup_point(point);
}
inline bool canonical_zk_proof(const key& statement, const zk_proof& proof, bool single_generator) {
  return sc_check(proof.z1.bytes) == 0 && sc_check(proof.z2.bytes) == 0 &&
      (!single_generator || proof.z2 == zero()) && canonical_subgroup_point(statement) &&
      canonical_subgroup_point(proof.R) && (single_generator || !(statement == identity()));
}
}
