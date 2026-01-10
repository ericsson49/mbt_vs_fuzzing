# Fuzzing Tutorial for SloppyVM

This tutorial demonstrates using fuzzing to find bugs in the SloppyVM implementation, and explores the limitations of random fuzzing.

---

## Buggy implementation (v1)

The file [src/sloppyvm/implementations/v1.py](../src/sloppyvm/implementations/v1.py) contains a deliberately buggy implementation. Let's examine its known bugs:

### Bugs
#### Bug 1: Wrong Endianness for PUSH4

**Location**: `src/sloppyvm/implementations/v1.py` (PUSH4 deserialization)

```python
# BUG: Using little-endian instead of big-endian
value = int.from_bytes(bytecode[offset + 1:offset + 5], 'little')
```

#### Bug 2: No Stack Underflow Checking

**Location**: `src/sloppyvm/implementations/v1.py` (ADD, MUL, and BYTE operations)


```python
# BUG: No stack underflow checking
a = stack.pop()  # Crashes if stack is empty!
b = stack.pop()
```

The implementation will raise `IndexError`. An (implicit) requirement is that it only should raise `SloppyVMException`, any other is interpreted as a crash.

#### Bug 3: Missing 64-bit Overflow Masking

**Location**: `src/sloppyvm/implementations/v1.py` (ADD and MUL result computation)

```python
# BUG: Missing modulo masking for overflow
stack.append(a + b)  # Should be: (a + b) & UINT64_MAX
...
stack.append(a * b)  # Should be: (a * b) & UINT64_MAX
```

#### Bug 4: Incorrect BYTE Instruction

**Location**: `src/sloppyvm/implementations/v1.py` (BYTE shift calculation)

```python
    shift = i * 8  # Should be: (7-i) * 8 for big-endian extraction
    result = (x >> shift) & 0xFF
```

#### Bug 5: Crash on Unknown Opcodes

**Location**: `src/sloppyvm/implementations/v1.py` (unknown opcode handler)

```python
else:
    # BUG: Unknown opcodes will crash
    raise RuntimeError(f"Unknown opcode: 0x{opcode:02X}")
```

The implementation raises `RuntimeError`. Again, it should only raise `SloppyVMException`.

### Fuzzing with random byte sequences

The simplest way to fuzz the Sloppy VM is to generate random byte sequences:

```python
def generate_random_bytes(max_length: int = 20) -> bytes:
    length = random.randint(1, max_length)
    return bytes(random.randint(0, 255) for _ in range(length))
```

This means most test cases are:
- Invalid opcodes (bytes 0x00, 0x05-0xFF)
- Truncated instructions (e.g., PUSH4 without 4 bytes of value)
- Malformed bytecode

We can run the fuzzer against v1 with 1000 random test cases:

```bash
uv run python -m sloppyvm.fuzzing.fuzzer -i v1 -n 1000 -g random
```

### Example Results

```bash
$ uv run python -m sloppyvm.fuzzing.fuzzer -i v1 -n 1000 -g random -s 42
============================================================
SloppyVM Fuzzer
Testing: v1
Generator: random
Running 1000 tests
============================================================

Test 1: Bug found
  Bytecode: 0c8c7d72
  Expected: ExceptionThrown(reason='invalid bytecode')
  Actual:   Crash(reason="implementation raised exception: RuntimeError('Unknown opcode: 0x0C')")

... (many more crash reports)

============================================================
Fuzzer Summary
----------------------------------------
Total tests run:           1000
Invalid bytecodes:         1000
Valid:                     0
Bugs found:                1000
Impl crashes:              1000
Correct:                   0
Bug detection rate:     100.0%
```

Random fuzzing excels at finding bugs like **Bug 5** (unknown opcode handling). Most random bytes are invalid opcodes, so this is discovered immediately:

```
Test 1: Bug found
Test 1: Bug found
  Bytecode: 0c8c7d72
  Expected: ExceptionThrown(reason='invalid bytecode')
  Actual:   Crash(reason="implementation raised exception: RuntimeError('Unknown opcode: 0x0C')")
```

Or like **Bug 2** (stack underflow): many ADD/MUL/BYTE instructions are executed before any value has been pushed.

```
Test 148: Bug found
  Bytecode: 0437dc4487bbcebb17cd1a63b99325c5e68f
  Expected: ExceptionThrown(reason='invalid bytecode')
  Actual:   Crash(reason="implementation raised exception: IndexError('pop from empty list')")
```

---

## Still buggy implementation (v2)

### Fixing bugs

The bugs are easy to fix: just raise `InvalidInstruction` or `StackUnderflow`, which are a sub-classes of `SloppyVMException`. After implementing the fixes, we have [src/sloppyvm/implementations/v2.py](../src/sloppyvm/implementations/v2.py).

### Fuzzing again

Let's fuzz the v2 version:

```bash
$ uv run python -m sloppyvm.fuzzing.fuzzer -i v2 -n 100000 -g random -s 42
============================================================
SloppyVM Fuzzer
Testing: v2
Generator: random
Running 100000 tests
============================================================

============================================================
Fuzzer Summary
----------------------------------------
Total tests run:           100000
Invalid bytecodes:         99922
Valid:                     78
Bugs found:                0
Impl crashes:              0
Correct:                   100000

No bugs detected!
```

Now, such simple fuzzing strategy is not able to reveal more bugs, even with 100,000 tests.

### Structure-aware fuzzing

Random byte sequences are good at finding shallow violations (unknown opcodes, stack underflow), but they struggle to find deeper semantic bugs. The problem is that most random bytes correspond to invalid opcodes, so we rarely exercise the actual logic of the VM.

**Structure-aware fuzzing** aims at generating random sequences of valid instructions. In our case, it can look like:

```python
def generate_structured_bytecode(max_instructions: int = 10) -> bytes:
    instructions = []
    num_instructions = random.randint(1, max_instructions)

    for _ in range(num_instructions):
        opcode = random.choice([0x01, 0x02, 0x03, 0x04])  # PUSH4, ADD, MUL, BYTE

        if opcode == 0x01:  # PUSH4
            value = random.randint(0, 0xFFFFFFFF)
            instructions.append(bytes([opcode]) + value.to_bytes(4, 'big'))
        else:  # ADD, MUL, BYTE (no operands)
            instructions.append(bytes([opcode]))

    return b''.join(instructions)
```

In practice, we may still generate invalid sequences with low probability, which is exactly the approach used in `src/sloppyvm/fuzzing/fuzzer.py` (the `generate_structure_aware_bytecode` function) when `-g structured` is passed to the fuzzer.

### Example Results

```bash
$ uv run python -m sloppyvm.fuzzing.fuzzer -i v2 -n 1000 -g structured -s 42
============================================================
SloppyVM Fuzzer
Testing: v2
Generator: structured
Running 1000 tests
============================================================

Test 26: Bug found
  Bytecode: 01983268560185d5169501b758588d014ccc9bc20301ff002d4d0143e42caf040401286218b8
    [PUSH4(value=2553440342), PUSH4(value=2245334677), PUSH4(value=3076020365), PUSH4(value=1288477634), MUL(), PUSH4(value=4278201677), PUSH4(value=1139027119), BYTE(), BYTE(), PUSH4(value=677517496)]
  Expected: Success(stack=[2553440342, 2245334677, 55, 677517496])
  Actual:   Success(stack=[2553440342, 2245334677, 0, 677517496])

============================================================
Fuzzer Summary
----------------------------------------
Total tests run:           1000
Invalid bytecodes:         237
Valid:                     763
Bugs found:                8
Impl crashes:              0
Correct:                   992
Bug detection rate:     0.8%
```

This time about 75% of bytecodes are valid, which helps to reveal **Bug 3** (64-bit overflow masking), **Bug 1** and **Bug 4** (little-endian instead of big-endian).

---

## Implementation with a more subtle bug (v3)

### Fixing bugs

After fixing the bugs, we've got [src/sloppyvm/implementations/v3.py](../src/sloppyvm/implementations/v3.py). In the process, one more bug revealed and fixed:
**Location**: `src/sloppyvm/implementations/v2.py` (BYTE stack pop order)
```python
# BUG: wrong stack pop order, should be swapped
x = stack.pop()
i = stack.pop()
```

### Structure-aware fuzzing again

```bash
$ uv run python -m sloppyvm.fuzzing.fuzzer -i v3 -n 1000000 -g structured -s 42
============================================================
SloppyVM Fuzzer
Testing: v3
Generator: structured
Running 1000000 tests
============================================================

============================================================
Fuzzer Summary
----------------------------------------
Total tests run:           1000000
Invalid bytecodes:         248087
Valid:                     751913
Bugs found:                0
Impl crashes:              0
Correct:                   1000000

No bugs detected!
```

Running 1 million tests revealed no bugs. However, there is still a bug present in `src/sloppyvm/implementations/v3.py` (BYTE boundary check):
```python
# BUG: wrong bound check
if i >= 7: # should be i >= 8
    stack.append(0)
else:
    # FIXED: Use (7-i) for big-endian indexing (0=MSB, 7=LSB)
    shift = (7 - i) * 8
    result = (x >> shift) & 0xFF
    stack.append(result)
```

It looks like it's extremely unlikely to generate a bytecode revealing the bug, even with structure-aware fuzzing. We'll address the problem with Model-based testing in the next [tutorial](./MBF_TUTORIAL.md).
