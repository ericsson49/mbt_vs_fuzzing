# MBT vs Fuzzing tutorial

## Overview

SloppyVM is intentionally simple: featuring just four instructions (PUSH4, ADD, MUL, BYTE), operating on 64-bit values. The project includes both a reference (correct) implementation and a deliberately buggy implementations to compare how effectively MBT and fuzzing can discover defects.

## Tutorials

- [(generation-based) Fuzzing Tutorial](docs/FUZZING_TUTORIAL.md) - Random and structure-aware fuzzing techniques
- [Model-Based Fuzzing Tutorial](docs/MBF_TUTORIAL.md) - Expression-based probabilistic generation
- [Enumeration-Based Testing Tutorial](docs/ENUMERATION_TUTORIAL.md) - Deterministic exhaustive test generation
- Mutation-based fuzzing (todo)
- MBT+mutative fuzzing (todo)


## Installation

This project uses `uv` for Python package management.

```bash
# Install dependencies
uv sync
```

## Usage

### Running Tests

```bash
# Run all tests
uv run pytest tests/

# Run specific test file
uv run pytest tests/test_spec.py
```

### Running the Fuzzer

```bash
uv run python -m sloppyvm.fuzzing.fuzzer [-h] [-n NUM_TESTS] [-s SEED] [-i {v1,v2,v3,v4}] [-g {random,structured,expression,mixed,enumeration}] [--max-expr-depth {0,1,2,3}]
```

Examples:
```bash
# Test v1 with 1000 random tests
uv run python -m sloppyvm.fuzzing.fuzzer -i v1 -n 1000 -g random

# Test v2 with structure-aware generation
uv run python -m sloppyvm.fuzzing.fuzzer -i v2 -n 10000 -g structured

# Test v3 with expression-based generation
uv run python -m sloppyvm.fuzzing.fuzzer -i v3 -g expression

# Test with mixed strategy (recommended for probabilistic fuzzing)
uv run python -m sloppyvm.fuzzing.fuzzer -i v1 -g mixed -s 42

# Test with enumeration - complete suite at depth 2 (default, ~120K tests)
uv run python -m sloppyvm.fuzzing.fuzzer -i v3 -g enumeration

# Test with enumeration - smaller suite at depth 1 (~266 tests)
uv run python -m sloppyvm.fuzzing.fuzzer -i v3 -g enumeration --max-expr-depth 1

# Test with enumeration - partial suite for quick testing
uv run python -m sloppyvm.fuzzing.fuzzer -i v3 -g enumeration -n 100
```

## Project Structure

```
mbt_vs_fuzzing/
├── src/sloppyvm/              # Main package
│   ├── spec.py                # Reference VM implementation (oracle)
│   ├── registry.py            # Dynamic implementation discovery
│   ├── implementations/       # Buggy implementations
│   │   ├── v1.py              # All bugs (endianness, overflow, etc.)
│   │   ├── v2.py              # Fixes shallow bugs, keeps semantic bugs
│   │   ├── v3.py              # Fixes overflow, keeps boundary bug
│   │   └── v4.py              # Fully correct implementation
│   └── fuzzing/               # Fuzzing framework
│       ├── fuzzer.py          # Main fuzzer with 5 strategies
│       ├── expression.py      # Expression ADT & compiler
│       ├── enumeration.py     # Exhaustive enumeration utilities
│       └── emulation.py       # Bytecode to Python translator
├── tests/                     # Test suite
│   ├── test_spec.py           # Unit tests for VM
│   ├── test_vectors.py        # Test vectors for analysis
│   ├── test_analysis.py       # Comprehensive analysis
│   └── test_enumeration.py    # Enumeration testing
└── docs/                      # Documentation
    ├── FUZZING_TUTORIAL.md
    ├── MBF_TUTORIAL.md
    └── ENUMERATION_TUTORIAL.md
```

### Key Components

**Core VM** ([src/sloppyvm/spec.py](src/sloppyvm/spec.py)):
- Reference implementation (the oracle)
- Four instructions: `PUSH4`, `ADD`, `MUL`, `BYTE`
- 64-bit stack-based architecture
- Big-endian serialization

**Buggy Implementations** ([src/sloppyvm/implementations/](src/sloppyvm/implementations/)):
- v1: All bugs present (crashes on errors)
- v2: Handles exceptions properly, semantic bugs remain
- v3: Fixes overflow bugs, boundary check bug remains
- v4: Fully correct implementation

**Fuzzing Framework** ([src/sloppyvm/fuzzing/](src/sloppyvm/fuzzing/)):
- Five generation strategies: random, structured, expression, mixed, enumeration
- Differential testing against reference implementation
- Exhaustive enumeration for bounded models
- Automatic implementation discovery

