## reachability.nim -- Enumerate reachable permissions from a principal.
##
## Given a set of role/group memberships and policies, compute all permissions
## transitively reachable by a principal.

{.experimental: "strict_funcs".}

import std/[sets, tables, hashes]
import lattice

# =====================================================================================================================
# Types
# =====================================================================================================================

type
  Membership* = object
    subject*: string  ## user or group
    group*: string    ## group or role

  Permission* = object
    action*: string
    resource*: string

func hash*(p: Permission): Hash =
  var h: Hash = 0
  h = h !& hash(p.action)
  h = h !& hash(p.resource)
  !$h

func `==`*(a, b: Permission): bool =
  a.action == b.action and a.resource == b.resource

# =====================================================================================================================
# Transitive closure
# =====================================================================================================================

proc transitive_groups*(principal: string, memberships: seq[Membership]): HashSet[string] =
  ## Compute all groups/roles transitively reachable from principal.
  result.incl(principal)
  var frontier = @[principal]
  while frontier.len > 0:
    var next_frontier: seq[string]
    for node in frontier:
      for m in memberships:
        if m.subject == node and m.group notin result:
          result.incl(m.group)
          next_frontier.add(m.group)
    frontier = next_frontier

proc reachable_permissions*(principal: string, memberships: seq[Membership],
                            role_permissions: Table[string, seq[Permission]]
                           ): Result[HashSet[Permission], SatisPortaError] =
  ## Enumerate all permissions reachable by principal through transitive group membership.
  let groups = transitive_groups(principal, memberships)
  var perms: HashSet[Permission]
  for g in groups:
    if g in role_permissions:
      for p in role_permissions[g]:
        perms.incl(p)
  Result[HashSet[Permission], SatisPortaError].good(perms)

proc compare_permissions*(principal_a, principal_b: string,
                          memberships: seq[Membership],
                          role_permissions: Table[string, seq[Permission]]
                         ): Result[tuple[only_a: HashSet[Permission], only_b: HashSet[Permission], shared: HashSet[Permission]], SatisPortaError] =
  ## Compare permissions between two principals.
  let perms_a = reachable_permissions(principal_a, memberships, role_permissions)
  if perms_a.is_bad: return Result[tuple[only_a: HashSet[Permission], only_b: HashSet[Permission], shared: HashSet[Permission]], SatisPortaError].bad(perms_a.err)
  let perms_b = reachable_permissions(principal_b, memberships, role_permissions)
  if perms_b.is_bad: return Result[tuple[only_a: HashSet[Permission], only_b: HashSet[Permission], shared: HashSet[Permission]], SatisPortaError].bad(perms_b.err)
  let shared = perms_a.val * perms_b.val
  let only_a = perms_a.val - perms_b.val
  let only_b = perms_b.val - perms_a.val
  Result[tuple[only_a: HashSet[Permission], only_b: HashSet[Permission], shared: HashSet[Permission]], SatisPortaError].good((only_a: only_a, only_b: only_b, shared: shared))
