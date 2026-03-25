# Choice/Life Adoption Plan: satisporta

## Summary

- **Error type**: `SatisPortaError` defined in lattice.nim -- move to `encode.nim`
- **Files to modify**: 4 + re-export module
- **Result sites**: 21
- **Life**: Not applicable

## Steps

1. Delete `src/satisporta/lattice.nim`
2. Move `SatisPortaError* = object of CatchableError` to `src/satisporta/encode.nim`
3. Add `requires "basis >= 0.1.0"` to nimble
4. In every file importing lattice:
   - Replace `import.*lattice` with `import basis/code/choice`
   - Replace `Result[T, E].good(v)` with `good(v)`
   - Replace `Result[T, E].bad(e[])` with `bad[T]("satisporta", e.msg)`
   - Replace `Result[T, E].bad(SatisPortaError(msg: "x"))` with `bad[T]("satisporta", "x")`
   - Replace return type `Result[T, SatisPortaError]` with `Choice[T]`
5. Update re-export: `export lattice` -> `export choice`
6. Update tests
