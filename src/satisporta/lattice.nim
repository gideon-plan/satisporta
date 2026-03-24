## lattice.nim -- Minimal result lattice for satisporta.

{.experimental: "strict_funcs".}

type
  Result*[T, E] = object
    case ok*: bool
    of true:  val*: T
    of false: err*: E

  MaybeKind* = enum
    mkGood, mkNone, mkBad

  Maybe*[T, E] = object
    case kind*: MaybeKind
    of mkGood: val*: T
    of mkNone: discard
    of mkBad:  err*: E

  SatisPortaError* = object of CatchableError

func good*[T, E](R: typedesc[Result[T, E]], val: T): Result[T, E] =
  Result[T, E](ok: true, val: val)

func bad*[T, E](R: typedesc[Result[T, E]], err: E): Result[T, E] =
  Result[T, E](ok: false, err: err)

func good*[T, E](M: typedesc[Maybe[T, E]], val: T): Maybe[T, E] =
  Maybe[T, E](kind: mkGood, val: val)

func none*[T, E](M: typedesc[Maybe[T, E]]): Maybe[T, E] =
  Maybe[T, E](kind: mkNone)

func bad*[T, E](M: typedesc[Maybe[T, E]], err: E): Maybe[T, E] =
  Maybe[T, E](kind: mkBad, err: err)

func is_good*[T, E](r: Result[T, E]): bool = r.ok
func is_bad*[T, E](r: Result[T, E]): bool = not r.ok
func is_good*[T, E](m: Maybe[T, E]): bool = m.kind == mkGood
func is_none*[T, E](m: Maybe[T, E]): bool = m.kind == mkNone
func is_bad*[T, E](m: Maybe[T, E]): bool = m.kind == mkBad

func get_or*[T, E](r: Result[T, E], default: T): T =
  if r.ok: r.val else: default

func get_or*[T, E](m: Maybe[T, E], default: T): T =
  if m.kind == mkGood: m.val else: default
