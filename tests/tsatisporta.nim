## tsatisporta.nim -- Tests for satisporta formal auth verification.

{.experimental: "strict_funcs".}

import std/[unittest, strutils, sequtils, tables, sets]
import satisporta

# =====================================================================================================================
# Encoding tests
# =====================================================================================================================

suite "encode":
  test "encode_model creates variables":
    let result = encode_model(
      @["alice", "bob"], @["read", "write"], @["file1"],
      @[("allow_alice_read", PolicyEffect.Permit, @[SmtVar(principal: "alice", action: "read", resource: "file1")])])
    check result.is_good
    check result.val.variables.len == 4  # 2 principals * 2 actions * 1 resource
    check result.val.policies.len == 1

  test "var_name format":
    let v = SmtVar(principal: "alice", action: "read", resource: "file1")
    check var_name(v) == "perm_alice_read_file1"

  test "to_smtlib generates valid output":
    let model = encode_model(
      @["alice"], @["read"], @["file1"],
      @[("p1", PolicyEffect.Permit, @[SmtVar(principal: "alice", action: "read", resource: "file1")])])
    check model.is_good
    let smt = to_smtlib(model.val)
    check smt.contains("declare-const")
    check smt.contains("check-sat")
    check smt.contains("perm_alice_read_file1")

# =====================================================================================================================
# Verification tests
# =====================================================================================================================

suite "verify":
  test "no conflicts when policies are disjoint":
    let model = encode_model(
      @["alice", "bob"], @["read"], @["file1"],
      @[("p1", PolicyEffect.Permit, @[SmtVar(principal: "alice", action: "read", resource: "file1")]),
        ("p2", PolicyEffect.Deny, @[SmtVar(principal: "bob", action: "read", resource: "file1")])])
    check model.is_good
    let result = check_conflicts(model.val)
    check result.is_good
    check result.val.result_code == VerifyResult.Satisfied

  test "detect conflict when same triple permitted and denied":
    let v = SmtVar(principal: "alice", action: "read", resource: "file1")
    let model = encode_model(
      @["alice"], @["read"], @["file1"],
      @[("p1", PolicyEffect.Permit, @[v]), ("p2", PolicyEffect.Deny, @[v])])
    check model.is_good
    let result = check_conflicts(model.val)
    check result.is_good
    check result.val.result_code == VerifyResult.Violated

  test "coverage check detects uncovered triples":
    let model = encode_model(
      @["alice", "bob"], @["read"], @["file1"],
      @[("p1", PolicyEffect.Permit, @[SmtVar(principal: "alice", action: "read", resource: "file1")])])
    check model.is_good
    let result = check_coverage(model.val)
    check result.is_good
    check result.val.result_code == VerifyResult.Violated  # bob:read:file1 uncovered

  test "full coverage passes":
    let model = encode_model(
      @["alice"], @["read"], @["file1"],
      @[("p1", PolicyEffect.Permit, @[SmtVar(principal: "alice", action: "read", resource: "file1")])])
    check model.is_good
    let result = check_coverage(model.val)
    check result.is_good
    check result.val.result_code == VerifyResult.Satisfied

  test "verify_all returns all checks":
    let model = encode_model(
      @["alice"], @["read"], @["file1"],
      @[("p1", PolicyEffect.Permit, @[SmtVar(principal: "alice", action: "read", resource: "file1")])])
    check model.is_good
    let result = verify_all(model.val)
    check result.is_good
    check result.val.len >= 2  # conflict-free + coverage + least-privilege

# =====================================================================================================================
# Counterexample tests
# =====================================================================================================================

suite "counterexample":
  test "extract from violated check":
    let checks = @[PropertyCheck(property: "conflict-free", result_code: VerifyResult.Violated,
                                 details: "Conflicting policies on: alice:read:file1")]
    let model = encode_model(@["alice"], @["read"], @["file1"], @[])
    check model.is_good
    let ces = extract_counterexamples(checks, model.val)
    check ces.len == 1
    check ces[0].violations.len == 1
    check ces[0].violations[0].principal == "alice"

  test "no counterexamples when satisfied":
    let checks = @[PropertyCheck(property: "conflict-free", result_code: VerifyResult.Satisfied, details: "")]
    let model = encode_model(@["alice"], @["read"], @["file1"], @[])
    check model.is_good
    let ces = extract_counterexamples(checks, model.val)
    check ces.len == 0

# =====================================================================================================================
# Reachability tests
# =====================================================================================================================

suite "reachability":
  test "transitive groups":
    let memberships = @[
      Membership(subject: "alice", group: "devs"),
      Membership(subject: "devs", group: "engineering"),
      Membership(subject: "engineering", group: "company")]
    let groups = transitive_groups("alice", memberships)
    check "alice" in groups
    check "devs" in groups
    check "engineering" in groups
    check "company" in groups

  test "reachable permissions through roles":
    let memberships = @[
      Membership(subject: "alice", group: "devs"),
      Membership(subject: "devs", group: "reader_role")]
    var role_perms: Table[string, seq[Permission]]
    role_perms["reader_role"] = @[Permission(action: "read", resource: "repo")]
    let result = reachable_permissions("alice", memberships, role_perms)
    check result.is_good
    check result.val.len == 1
    let p = result.val.toSeq[0]
    check p.action == "read"
    check p.resource == "repo"

  test "compare permissions":
    let memberships = @[
      Membership(subject: "alice", group: "admin"),
      Membership(subject: "bob", group: "viewer")]
    var role_perms: Table[string, seq[Permission]]
    role_perms["admin"] = @[Permission(action: "read", resource: "r1"), Permission(action: "write", resource: "r1")]
    role_perms["viewer"] = @[Permission(action: "read", resource: "r1")]
    let result = compare_permissions("alice", "bob", memberships, role_perms)
    check result.is_good
    check result.val.only_a.len == 1  # alice has write, bob doesn't
    check result.val.shared.len == 1  # both have read
    check result.val.only_b.len == 0
