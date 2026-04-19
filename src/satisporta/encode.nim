## encode.nim -- Translate porta policies/entities into SMT assertions.
##
## Maps porta's authorization model (principals, actions, resources, policies)
## into boolean SMT variables and constraints for Z3.

{.experimental: "strict_funcs".}

import std/[strutils, hashes]
import basis/code/choice

# =====================================================================================================================
# Types
# =====================================================================================================================

type
  SmtVar* = object
    ## A boolean variable representing "principal P can perform action A on resource R".
    principal*: string
    action*: string
    resource*: string

  PolicyEffect* {.pure.} = enum
    Permit
    Deny

  EncodedPolicy* = object
    ## A single policy translated to SMT constraint.
    name*: string
    effect*: PolicyEffect
    vars*: seq[SmtVar]  ## Variables this policy applies to

  SmtEncoding* = object
    ## Complete SMT encoding of an authorization model.
    variables*: seq[SmtVar]
    policies*: seq[EncodedPolicy]
    principals*: seq[string]
    actions*: seq[string]
    resources*: seq[string]

func hash*(v: SmtVar): Hash =
  var h: Hash = 0
  h = h !& hash(v.principal)
  h = h !& hash(v.action)
  h = h !& hash(v.resource)
  !$h

func `==`*(a, b: SmtVar): bool =
  a.principal == b.principal and a.action == b.action and a.resource == b.resource

# =====================================================================================================================
# Variable naming
# =====================================================================================================================

proc var_name*(v: SmtVar): string =
  ## Generate a unique SMT variable name.
  "perm_" & v.principal & "_" & v.action & "_" & v.resource

# =====================================================================================================================
# Encoding
# =====================================================================================================================

proc encode_model*(principals, actions, resources: seq[string],
                   policies: seq[(string, PolicyEffect, seq[SmtVar])]
                  ): Choice[SmtEncoding] =
  ## Encode an authorization model into SMT representation.
  ## Each (principal, action, resource) triple becomes a boolean variable.
  ## Each policy constrains which variables are true/false.
  var vars: seq[SmtVar]
  for p in principals:
    for a in actions:
      for r in resources:
        vars.add(SmtVar(principal: p, action: a, resource: r))
  var encoded_policies: seq[EncodedPolicy]
  for (name, effect, pvars) in policies:
    encoded_policies.add(EncodedPolicy(name: name, effect: effect, vars: pvars))
  good(
    SmtEncoding(variables: vars, policies: encoded_policies,
                principals: principals, actions: actions, resources: resources))

proc to_smtlib*(encoding: SmtEncoding): string =
  ## Generate SMT-LIB2 string from encoding.
  var lines: seq[string]
  lines.add("(set-logic QF_UF)")
  # Declare boolean variables
  for v in encoding.variables:
    lines.add("(declare-const " & var_name(v) & " Bool)")
  # Assert policy constraints
  for pol in encoding.policies:
    for v in pol.vars:
      let vn = var_name(v)
      case pol.effect
      of PolicyEffect.Permit:
        lines.add("(assert " & vn & ")  ; " & pol.name & " permits")
      of PolicyEffect.Deny:
        lines.add("(assert (not " & vn & "))  ; " & pol.name & " denies")
  lines.add("(check-sat)")
  lines.add("(get-model)")
  lines.join("\n")
