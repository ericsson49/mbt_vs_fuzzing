# MBT vs Fuzzing tutorial

## Overview

SloppyVM is intentionally simple: featuring just four instructions (PUSH4, ADD, MUL, BYTE), operating on 64-bit values. The project includes both a reference (correct) implementation and a deliberately buggy implementations to compare how effectively MBT and fuzzing can discover defects.

## Tutorials

- [fuzzing tutorial](FUZZING_TUTORIAL.md)
- model-based testing (todo)

## Installation

This project uses `uv` for Python package management.

```bash
# Install dependencies
uv sync
```

## Usage

### Running Tests

```bash
uv run test_sloppy_vm.py
```

### Running Python Scripts

```bash
uv run <script>.py
```

E.g. running fuzzer
```bash
uv run fuzzer.py [-h] [-n NUM_TESTS] [-s SEED] [-i {v1,v2,v3}] [-g {random,structured}]
```

## Project Structure

- [sloppy_vm_spec.py](sloppy_vm_spec.py): Reference VM implementation (correct), serves as the test oracle
- [test_sloppy_vm.py](test_sloppy_vm.py): Test suite for serialization and execution
- [sloppy_vm_impl_v1.py](sloppy_vm_impl_v1.py), [sloppy_vm_impl_v2.py](sloppy_vm_impl_v2.py), [sloppy_vm_impl_v3.py](sloppy_vm_impl_v3.py): Deliberately buggy implementations.

