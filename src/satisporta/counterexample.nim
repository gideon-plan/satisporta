## counterexample.nim -- Extract violating assignments from verification results.

{.experimental: "strict_funcs".}

import std/[strutils]
import encode, verify

# =====================================================================================================================
# Types
# =====================================================================================================================

type
  Counterexample* = object
    property*: string
    violations*: seq[SmtVar]
    description*: string

# =====================================================================================================================
# Extraction
# =====================================================================================================================

proc extract_counterexamples*(checks: seq[PropertyCheck],
                              encoding: SmtEncoding
                             ): seq[Counterexample] =
  ## Extract counterexamples from violated property checks.
  for check in checks:
    if check.result_code == VerifyResult.Violated:
      var ce = Counterexample(property: check.property, description: check.details)
      # Parse violated variable names from details
      if check.details.contains(":"):
        let parts = check.details.split(": ", 1)
        if parts.len > 1:
          let var_strs = parts[1].split(", ")
          for vs in var_strs:
            let fields = vs.split(":")
            if fields.len == 3:
              ce.violations.add(SmtVar(principal: fields[0], action: fields[1], resource: fields[2]))
            elif fields.len == 2:
              # action:resource from least-privilege
              ce.violations.add(SmtVar(principal: "", action: fields[0], resource: fields[1]))
      result.add(ce)

proc format_counterexample*(ce: Counterexample): string =
  ## Human-readable counterexample.
  var lines: seq[string]
  lines.add("Property violated: " & ce.property)
  lines.add("Description: " & ce.description)
  for v in ce.violations:
    if v.principal.len > 0:
      lines.add("  - " & v.principal & " " & v.action & " " & v.resource)
    else:
      lines.add("  - " & v.action & " " & v.resource)
  lines.join("\n")
