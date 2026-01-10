# (Enumerative) Model-Based Testing for SloppyVM

This tutorial explores deterministic, exhaustive test generation through systematic enumeration of bounded model spaces.

---

## Limitations of Randomized Testing

Randomized testing can be very efficient, but it lacks deterministic coverage guarantees. In the [Model-Based Fuzzing tutorial](./MBF_TUTORIAL.md), expression-based fuzzing with tuned constant generation found the BYTE boundary bug in v3. However, probabilistic sampling doesn't guarantee the bug will be found in every run:

```bash
# Seed 1: no bugs found
$ uv run python -m sloppyvm.fuzzing.fuzzer -i v3 -g expression -n 100 -s 1
...
No bugs detected!

# Seed 2: bug found
$ uv run python -m sloppyvm.fuzzing.fuzzer -i v3 -g expression -n 100 -s 2
...
Test 88: Bug found
```

How do we guarantee coverage of important scenarios?

---

## Finite Models

As a solution, we can describe a set of **tests requirements** with a finite model. 

Finite models can provide deterministic coverage. We can associate each model solution with a **test requirement**:
- **Coverage criterion**: Model completeness defines test completeness
- **Enumeration**: Generate tests by enumerating all model solutions

For SloppyVM expressions with depth ≤ 2 and 4 constants `{0, 1, 7, 8}`:
- Depth 0: 4 expressions
- Depth 1: 52 expressions
- Depth 2: 8,116 expressions

This is small enough to enumerate exhaustively.

---

## Expression Model Components

### Expression Tree Structure

The expression model defines an AST in [src/sloppyvm/fuzzing/expression.py](../src/sloppyvm/fuzzing/expression.py):

```python
class Const:
    value: int

class Add:
    left: Expr
    right: Expr

class Mul:
    left: Expr
    right: Expr

class Byte:
    value: Expr
    index: Expr

Expr = Union[Const, Add, Mul, Byte]
```

The set of all expressions is infinite, but it is easy to bound by limiting expression depth.

### Bounding the Constant Space

PUSH4 accepts any 32-bit value (4 billion possibilities). We need to select interesting values using [boundary value analysis](https://en.wikipedia.org/wiki/Boundary-value_analysis).

**BYTE instruction boundaries:**
- `i >= 8` check in spec suggests two ranges: `[0-7]` and `[8+]`
- Boundary values for `i`: `0`, `7`, `8`

**Arithmetic overflow boundaries:**
- `0`: Zero value
- `1`: Identity element
- `0xFF`: Byte max
- `0xFFFF`: 16-bit max
- `0xFFFFFFFF`: 32-bit max (PUSH4 limit)

**Combined constant set:** `{0, 1, 7, 8}` covers critical BYTE boundaries. A more comprehensive set: `{0, 1, 2, 7, 8, 0xFF, 0xFFFF, 0xFFFFFFFF}` adds arithmetic boundaries.

### Systematic Enumeration

The [enumeration](../src/sloppyvm/fuzzing/enumeration.py) module generates all expressions up to a given depth:

```python
def enumerate_expressions(depth: int, constants: List[int]) -> Iterator[Expr]:
    if depth == 0:
        for c in constants:
            yield Const(c)
    else:
        sub_exprs = list(enumerate_expressions(depth - 1, constants))
        for left in sub_exprs:
            for right in sub_exprs:
                yield Add(left, right)
                yield Mul(left, right)
                yield Byte(left, right)
        for c in constants:
            yield Const(c)
```

This recursively generates all combinations without repetition.

### Complete Test Suite Composition

The `generate_comprehensive_suite` function inn [fuenumerationzzer.py](../src/sloppyvm/fuzzing/enumeration.py) combines multiple test categories:

1. **Expression programs** (depth 0-2):
   - 4 constants: ~8,100 unique programs
   - 8 constants: ~120,000 unique programs

2. **BYTE boundary tests** (60 tests):
   - 6 values × 10 indices (0-9)
   - Targets index boundary conditions

3. **Arithmetic overflow tests** (18 tests):
   - Large value pairs for ADD/MUL
   - Tests 64-bit wrapping behavior

4. **Stack underflow tests** (15 tests):
   - Operations without sufficient stack
   - Verifies exception handling

**Total:** ~8,193 tests (minimal) or ~120,074 tests (default), all deterministic.

### Beyond Expression Enumeration

While expressions guarantee no stack underflow (compilation ensures balanced stack), we also need to test error conditions. Direct instruction sequences can test:

**Stack underflow scenarios:**
```python
[ADD()]                    # No values on stack
[PUSH4(1), ADD()]         # Only one value (need two)
```

**64-bit arithmetic overflow:**
```python
[PUSH4(0xFFFFFFFF), PUSH4(0xFFFFFFFF), MUL()]  # 32-bit × 32-bit = 64-bit
```

These targeted tests complement expression enumeration.

---

## Running Enumeration Tests

### Basic Usage

```bash
# Complete suite at depth 2 (~120K tests, default)
$ uv run python -m sloppyvm.fuzzing.fuzzer -i v3 -g enumeration

# Smaller suite at depth 1 (~266 tests)
$ uv run python -m sloppyvm.fuzzing.fuzzer -i v3 -g enumeration --max-expr-depth 1

# Partial suite for debugging (first 100 tests)
$ uv run python -m sloppyvm.fuzzing.fuzzer -i v3 -g enumeration -n 100
```

**Configuration:**
- `--max-expr-depth`: Controls suite size (0-3)
- `-n`: Optional limit (omit for complete suite)
- Deterministic: same parameters → identical tests

### Finding the v3 BYTE Bug

Running with depth 1 (266 tests total):

```bash
$ uv run python -m sloppyvm.fuzzing.fuzzer -i v3 -g enumeration --max-expr-depth 1
Generating complete enumeration suite (max expression depth: 1)...
Generated 266 unique test cases
============================================================
SloppyVM Fuzzer
Testing: v3
Generator: enumeration
Running 266 tests
============================================================

Test 36: Bug found
  Bytecode: 0100000001010000000704
    [PUSH4(value=1), PUSH4(value=7), BYTE()]
  Expected: Success(stack=[1])
  Actual:   Success(stack=[0])

Test 37: Bug found
  Bytecode: 0100000002010000000704
    [PUSH4(value=2), PUSH4(value=7), BYTE()]
  Expected: Success(stack=[2])
  Actual:   Success(stack=[0])

============================================================
Fuzzer Summary
----------------------------------------
Total tests run:           266
Invalid bytecodes:         0
Valid:                     266
Bugs found:                8
Impl crashes:              0
Correct:                   258
Bug detection rate:     3.0%
```

All 8 failing tests involve `BYTE(x, 7)` - exactly the boundary condition from the v3 bug.

---

## Conclusion

Enumerative model-based testing provides deterministic, exhaustive coverage within bounded models. In practice, it makes sense to combine deterministic and randomized test generation: we can have both deterministic coverage guarantee and exploration of larger parts of the SUT state space. One straightforward approach is to use deterministically generated test suite as a seed corupus for mutation-based fuzzing.

