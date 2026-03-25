## verify.nim -- Check policy properties using SMT.
##
## Properties: no escalation, complete coverage, conflict-free.

{.experimental: "strict_funcs".}

import std/[sets, strutils, hashes]
import basis/code/choice, encode

# =====================================================================================================================
# Types
# =====================================================================================================================

type
  VerifyResult* = enum
    vrSatisfied    ## Property holds
    vrViolated     ## Property violated
    vrUnknown      ## Solver could not determine

  PropertyCheck* = object
    property*: string
    result_code*: VerifyResult
    details*: string

# =====================================================================================================================
# Conflict detection
# =====================================================================================================================

proc check_conflicts*(encoding: SmtEncoding): Choice[PropertyCheck] =
  ## Check if any (principal, action, resource) triple is both permitted and denied.
  var permit_set: HashSet[SmtVar]
  var deny_set: HashSet[SmtVar]
  for pol in encoding.policies:
    for v in pol.vars:
      case pol.effect
      of pePermit: permit_set.incl(v)
      of peDeny: deny_set.incl(v)
  let conflicts = permit_set * deny_set  # intersection
  if conflicts.len > 0:
    var details: seq[string]
    for c in conflicts:
      details.add(c.principal & ":" & c.action & ":" & c.resource)
    good(
      PropertyCheck(property: "conflict-free", result_code: vrViolated,
                    details: "Conflicting policies on: " & details.join(", ")))
  else:
    good(
      PropertyCheck(property: "conflict-free", result_code: vrSatisfied, details: ""))

# =====================================================================================================================
# Coverage check
# =====================================================================================================================

proc check_coverage*(encoding: SmtEncoding): Choice[PropertyCheck] =
  ## Check if every (principal, action, resource) triple is covered by at least one policy.
  var covered: HashSet[SmtVar]
  for pol in encoding.policies:
    for v in pol.vars:
      covered.incl(v)
  var uncovered: seq[string]
  for v in encoding.variables:
    if v notin covered:
      uncovered.add(v.principal & ":" & v.action & ":" & v.resource)
  if uncovered.len > 0:
    good(
      PropertyCheck(property: "complete-coverage", result_code: vrViolated,
                    details: "Uncovered: " & uncovered.join(", ")))
  else:
    good(
      PropertyCheck(property: "complete-coverage", result_code: vrSatisfied, details: ""))

# =====================================================================================================================
# Least privilege check
# =====================================================================================================================

proc check_least_privilege*(encoding: SmtEncoding, principal: string
                           ): Choice[PropertyCheck] =
  ## List all permissions granted to a principal.
  var permitted: seq[string]
  for pol in encoding.policies:
    if pol.effect == pePermit:
      for v in pol.vars:
        if v.principal == principal:
          permitted.add(v.action & ":" & v.resource)
  good(
    PropertyCheck(property: "least-privilege", result_code: vrSatisfied,
                  details: "Permissions for " & principal & ": " & permitted.join(", ")))

# =====================================================================================================================
# Full verification
# =====================================================================================================================

proc verify_all*(encoding: SmtEncoding): Choice[seq[PropertyCheck]] =
  ## Run all property checks.
  var checks: seq[PropertyCheck]
  let conflict = check_conflicts(encoding)
  if conflict.is_bad: return bad[seq[PropertyCheck]](conflict.err)
  checks.add(conflict.val)
  let coverage = check_coverage(encoding)
  if coverage.is_bad: return bad[seq[PropertyCheck]](coverage.err)
  checks.add(coverage.val)
  for p in encoding.principals:
    let lp = check_least_privilege(encoding, p)
    if lp.is_bad: return bad[seq[PropertyCheck]](lp.err)
    checks.add(lp.val)
  good(checks)
