"""
Enumeration-based test generation for SloppyVM.

This module provides exhaustive test generation by systematically enumerating
all possible programs within bounded model spaces. Unlike probabilistic fuzzing,
enumeration provides guaranteed coverage of the bounded model.
"""

import itertools
from typing import Iterator, List

from sloppyvm.spec import (
    PUSH4, ADD, MUL, BYTE,
    serialize_program
)
from .expression import Expr, Const, Add, Mul, Byte, compile_expr


# ============================================================
# Configuration
# ============================================================

# Interesting constants for boundary value analysis
BOUNDARY_CONSTANTS = [
    0,           # Zero
    1,           # One
    2,           # Small value
    7,           # BYTE boundary (max valid index)
    8,           # BYTE boundary (first invalid index)
    0xFF,        # Byte max
    0xFFFF,      # 16-bit max
    0xFFFFFFFF,  # 32-bit max (PUSH4 max)
]

# Minimal interesting constants for smaller test suites
MINIMAL_CONSTANTS = [0, 1, 7, 8]

# Basic instruction types (without operands)
BASIC_INSTRUCTIONS = [ADD, MUL, BYTE]


# ============================================================
# Expression Enumeration
# ============================================================

def enumerate_expressions(depth: int, constants: List[int]) -> Iterator[Expr]:
    """
    Exhaustively enumerate all expressions up to given depth.

    Args:
        depth: Maximum expression tree depth (0 = constants only)
        constants: List of constant values to use

    Yields:
        All possible expressions within the depth bound

    Example:
        depth=0: [Const(0), Const(1), ...]
        depth=1: All constants + Add(Const, Const), Mul(Const, Const), ...
    """
    if depth == 0:
        # Base case: only constants
        for c in constants:
            yield Const(c)
    else:
        # Recursive case: all combinations of operations
        # Generate sub-expressions at depth-1
        sub_exprs = list(enumerate_expressions(depth - 1, constants))

        # Binary operations: all pairs of sub-expressions
        for left in sub_exprs:
            for right in sub_exprs:
                yield Add(left, right)
                yield Mul(left, right)
                yield Byte(left, right)

        # Also include constants at this level
        for c in constants:
            yield Const(c)


def enumerate_expression_programs(max_depth: int,
                                 constants: List[int] = MINIMAL_CONSTANTS) -> Iterator[bytes]:
    """
    Enumerate all expression-based programs up to given depth.

    Args:
        max_depth: Maximum expression tree depth
        constants: List of constant values to use

    Yields:
        Serialized bytecode for each expression
    """
    for depth in range(max_depth + 1):
        for expr in enumerate_expressions(depth, constants):
            yield compile_expr(expr)


# ============================================================
# Boundary Value Tests
# ============================================================

def enumerate_byte_boundary_tests() -> Iterator[bytes]:
    """
    Enumerate all critical test cases for BYTE instruction.

    This specifically targets the boundary bug in v3 where the check
    is `if i >= 7` instead of `if i >= 8`.

    Yields:
        Bytecode testing BYTE instruction boundaries
    """
    # Test interesting values with indices 0-9
    test_values = [0, 1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0x123456789ABCDEF]
    test_indices = list(range(10))  # 0-9 covers all interesting cases

    for value in test_values:
        for index in test_indices:
            # Generate: PUSH4(value), PUSH4(index), BYTE
            # Note: value might be > UINT32_MAX, will be truncated by PUSH4
            yield serialize_program([
                PUSH4(value & 0xFFFFFFFF),
                PUSH4(index),
                BYTE()
            ])


def enumerate_arithmetic_overflow_tests() -> Iterator[bytes]:
    """
    Enumerate tests for arithmetic overflow behavior.

    Tests that ADD and MUL properly mask results to 64-bit.

    Yields:
        Bytecode testing overflow conditions
    """
    # Large values that will overflow when added/multiplied
    large_values = [0xFFFFFFFF, 0x80000000, 0x7FFFFFFF]

    # Test ADD overflow
    for v1 in large_values:
        for v2 in large_values:
            yield serialize_program([
                PUSH4(v1),
                PUSH4(v2),
                ADD()
            ])

    # Test MUL overflow
    for v1 in large_values:
        for v2 in large_values:
            yield serialize_program([
                PUSH4(v1),
                PUSH4(v2),
                MUL()
            ])


def enumerate_stack_underflow_tests() -> Iterator[bytes]:
    """
    Enumerate test cases that should trigger stack underflow.

    Yields:
        Bytecode that should raise StackUnderflow exception
    """
    # Operations without sufficient stack values
    yield serialize_program([ADD()])
    yield serialize_program([MUL()])
    yield serialize_program([BYTE()])

    # One value, but need two
    for value in MINIMAL_CONSTANTS:
        yield serialize_program([PUSH4(value), ADD()])
        yield serialize_program([PUSH4(value), MUL()])
        yield serialize_program([PUSH4(value), BYTE()])


# ============================================================
# Comprehensive Test Suites
# ============================================================

def generate_comprehensive_suite(max_expr_depth: int = 2) -> Iterator[bytes]:
    """
    Generate comprehensive exhaustive test suite with deduplication.

    Combines expression enumeration with targeted boundary tests, removing
    any duplicates to ensure each test is unique.

    Args:
        max_expr_depth: Maximum expression tree depth (2-3 recommended)

    Yields:
        Bytecode for comprehensive test suite (deduplicated)
    """
    seen = set()

    # All expression programs up to max depth
    for bytecode in enumerate_expression_programs(max_depth=max_expr_depth,
                                                 constants=BOUNDARY_CONSTANTS):
        hex_code = bytecode.hex()
        if hex_code not in seen:
            seen.add(hex_code)
            yield bytecode

    # All boundary tests (deduplicated)
    for bytecode in enumerate_byte_boundary_tests():
        hex_code = bytecode.hex()
        if hex_code not in seen:
            seen.add(hex_code)
            yield bytecode

    for bytecode in enumerate_arithmetic_overflow_tests():
        hex_code = bytecode.hex()
        if hex_code not in seen:
            seen.add(hex_code)
            yield bytecode

    for bytecode in enumerate_stack_underflow_tests():
        hex_code = bytecode.hex()
        if hex_code not in seen:
            seen.add(hex_code)
            yield bytecode
