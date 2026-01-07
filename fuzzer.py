"""
Simple fuzzer for SloppyVM - compares buggy implementations against spec.

Generates completely random byte sequences and compares results from:
- sloppy_vm_impl_v1.py (buggy implementation - crashes on unknown opcodes)
- sloppy_vm_impl_v2.py (buggy implementation - InvalidInstruction exception)
- sloppy_vm_impl_v3.py (bugs fixed)
- sloppy_vm_spec.py (reference implementation)
"""

from dataclasses import dataclass
import random
from typing import List, Optional

from sloppy_vm_spec import (
    deserialize_program, execute_program, SloppyVMException, InvalidInstruction,
    OP_PUSH4, OP_ADD, OP_MUL, OP_BYTE
)
import sloppy_vm_impl_v1
import sloppy_vm_impl_v2
import sloppy_vm_impl_v3
import sloppy_vm_impl_v4
from expression import random_expr, compile_expr, UINT32_MAX


def generate_random_bytes(max_length: int = 20) -> bytes:
    """Generate completely random bytes - no structure consideration."""
    length = random.randint(1, max_length)
    return bytes(random.randint(0, 255) for _ in range(length))


def generate_structure_aware_bytecode(max_instructions: int = 10) -> bytes:
    """
    Generate structure-aware bytecode with optional fuzzing.

    Creates valid instruction sequences (PUSH4, ADD, MUL, BYTE) that respect
    the serialization format, but can still generate invalid bytecode with
    some probability to test error handling.

    Args:
        max_instructions: Maximum number of instructions to generate

    Returns:
        Bytecode that may or may not be valid
    """
    # Otherwise, generate valid instruction sequences
    instructions = []

    # Generate random number of instructions
    num_instructions = random.randint(1, max_instructions)

    for _ in range(num_instructions):
        # Randomly choose an instruction type
        # Weight towards PUSH4 to ensure stack has values for binary ops
        # Include chance for invalid opcode (0x00, 0x05-0xFF)
        opcode_roll = random.random()

        if opcode_roll < 0.45:  # 45% chance - PUSH4
            value = random.randint(0, 0xFFFFFFFF)
            # Coin flip: generate truncated PUSH4 (invalid bytecode)
            if random.random() < 0.05:
                # Generate only 1-3 bytes of the value (truncated)
                value_bytes = value.to_bytes(4, 'big')
                truncate_to = random.randint(1, 3)
                instructions.append(bytes([OP_PUSH4]) + value_bytes[:truncate_to])
                break  # Stop generating after truncating
            else:
                instructions.append(bytes([OP_PUSH4]) + value.to_bytes(4, 'big'))
        elif opcode_roll < 0.65:  # 20% chance - ADD
            instructions.append(bytes([OP_ADD]))
        elif opcode_roll < 0.82:  # 17% chance - MUL
            instructions.append(bytes([OP_MUL]))
        elif opcode_roll < 0.97:  # 15% chance - BYTE
            instructions.append(bytes([OP_BYTE]))
        else:  # 3% chance - invalid opcode
            invalid_opcode = random.choice([0x00] + list(range(0x05, 0x100)))
            instructions.append(bytes([invalid_opcode]))
            break  # Stop after invalid opcode

    return b''.join(instructions)


def generate_expression_bytecode(
    max_depth: int = 3,
    max_value: int | None = None
) -> bytes:
    """
    Generate bytecode using expression trees.

    Creates random expression trees (Const, Add, Mul) and compiles them to
    valid SloppyVM bytecode. This guarantees syntactically valid bytecode
    that will execute successfully (no stack underflow or invalid opcodes).

    Args:
        max_depth: Maximum depth of the expression tree
        max_value: Maximum value for random constants. If None, uses default list
                   [0-9, UINT32_MAX]. Otherwise, uses rng.randint(0, max_value).

    Returns:
        Valid bytecode for a SloppyVM program
    """
    if max_value is None:
        # Default behavior: sample from specific values including edge cases
        const_values = [*range(0, 10), UINT32_MAX]
        def const_generator(rng: random.Random) -> int:
            return rng.choice(const_values)
    else:
        # Generate random values in range [0, max_value]
        def const_generator(rng: random.Random) -> int:
            return rng.randint(0, max_value)

    rng = random.Random()
    expr = random_expr(rng, max_depth=max_depth, const_generator=const_generator)
    return compile_expr(expr)


def generate_mixed_strategy_bytecode(max_instructions: int = 10) -> bytes:
    """
    Generate bytecode using a mixed strategy, randomly selecting between:
    1. Completely random bytes
    2. Structure-aware bytecode (with potential invalid bytecode)
    3. Expression bytecode with default values
    4. Expression bytecode with full uint32 range

    This combines the strengths of different generation approaches to maximize
    bug detection coverage.

    Args:
        max_instructions: Maximum number of instructions for structured/expression generators

    Returns:
        Bytecode generated using one of the four strategies
    """
    strategy_roll = random.random()

    if strategy_roll < 0.25:  # 25% chance - completely random
        return generate_random_bytes()
    elif strategy_roll < 0.50:  # 25% chance - structured
        return generate_structure_aware_bytecode(max_instructions=max_instructions)
    elif strategy_roll < 0.75:  # 25% chance - expression with default values
        return generate_expression_bytecode(max_depth=3, max_value=None)
    else:  # 25% chance - expression with full uint32 range
        return generate_expression_bytecode(max_depth=3, max_value=UINT32_MAX)


@dataclass(frozen=True)
class ExecutionResult:
    """Base class for execution results - used as a union type."""


@dataclass(frozen=True)
class ExceptionThrown(ExecutionResult):
    reason: str


@dataclass(frozen=True)
class Crash(ExecutionResult):
    reason: str


@dataclass(frozen=True)
class Success(ExecutionResult):
    stack: List[int]


def execute_with_spec(bytecode: bytes) -> ExecutionResult:
    try:
        instructions = deserialize_program(bytecode)
        result = execute_program(instructions)
        return Success(result.stack)
    except InvalidInstruction as e:
        return ExceptionThrown("invalid bytecode")
    except SloppyVMException as e:
        return ExceptionThrown(repr(e))


def execute_with_implementation(bytecode: bytes, impl_func):
    try:
        result = impl_func(bytecode)
        return Success(result)
    except SloppyVMException as e:
        return ExceptionThrown(repr(e))
    except Exception as e:
        return Crash(f"implementation raised exception: {repr(e)}")


def compare_results(expected: ExecutionResult, actual: ExecutionResult) -> bool:
    match expected:
        case Crash():
            return isinstance(actual, Crash)
        case ExceptionThrown():
            return isinstance(actual, ExceptionThrown)
        case Success():
            return expected == actual
        case _:
            raise TypeError(f"Unknown result: {expected}")


def run_fuzzer(
    num_tests: int = 1000,
    seed: Optional[int] = None,
    impl: str = "v1",
    generator: str = "random"
) -> None:
    """
    Run the fuzzer for a specified number of tests.

    Args:
        num_tests: Number of random test cases to generate
        seed: Random seed for reproducibility
        impl: Which implementation to test: "v1", "v2", "v3", or "v4"
        generator: Generator type: "random", "structured", "expression", or "mixed"
    """
    if seed is not None:
        random.seed(seed)

    # Select implementation
    if impl == "v1":
        impl_func = sloppy_vm_impl_v1.execute
        impl_name = "v1"
    elif impl == "v2":
        impl_func = sloppy_vm_impl_v2.execute
        impl_name = "v2"
    elif impl == "v3":
        impl_func = sloppy_vm_impl_v3.execute
        impl_name = "v3"
    elif impl == "v4":
        impl_func = sloppy_vm_impl_v4.execute
        impl_name = "v4"
    else:
        raise ValueError(f"Unknown implementation: {impl}. Use 'v1', 'v2', 'v3', or 'v4'")

    print(f"SloppyVM Fuzzer - Running {num_tests} tests")
    print(f"Testing: {impl_name}")
    print(f"Generator: {generator}")
    print("=" * 60)

    bugs_found = 0
    crashes = 0   # Impl raised unexpected exception
    invalid_bytecodes = 0

    for i in range(num_tests):
        # Generate test input using selected generator
        if generator == "expression":
            bytecode = generate_expression_bytecode()
        elif generator == "structured":
            bytecode = generate_structure_aware_bytecode()
        elif generator == "mixed":
            bytecode = generate_mixed_strategy_bytecode()
        else:  # random
            bytecode = generate_random_bytes()

        # Run spec implementation - returns None for invalid bytecode (never raises)
        spec_result = execute_with_spec(bytecode)

        if spec_result == ExceptionThrown("invalid bytecode"):
            invalid_bytecodes += 1

        # Run implementation under test - may raise exceptions
        impl_result = execute_with_implementation(bytecode, impl_func)

        if isinstance(impl_result, Crash):
            crashes += 1

        # Analyze the results
        if not compare_results(spec_result, impl_result):
            bugs_found += 1
            print(f"\nTest {i+1}: Bug found")
            print(f"  Bytecode: {bytecode.hex()}")
            try:
                instructions = deserialize_program(bytecode)
                print(f"    {instructions}")
            except InvalidInstruction:
                pass
            print(f"  Expected: {spec_result}")
            print(f"  Actual:   {impl_result}")

    # Summary
    print("\n" + "=" * 60)
    print("Fuzzer Summary")
    print("-" * 40)
    print(f"Total tests run:           {num_tests}")
    print(f"Invalid bytecodes:         {invalid_bytecodes}")
    print(f"Valid:                     {num_tests - invalid_bytecodes}")
    print(f"Bugs found:                {bugs_found}")
    print(f"Impl crashes:              {crashes}")
    print(f"Correct:                   {num_tests - bugs_found}")

    if bugs_found > 0:
        bug_rate = (bugs_found / num_tests) * 100
        print(f"Bug detection rate:     {bug_rate:.1f}%")
    else:
        print("\nNo bugs detected in valid test cases!")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fuzzer for SloppyVM")
    parser.add_argument(
        "-n", "--num-tests",
        type=int,
        default=1000,
        help="Number of random test cases to run (default: 1000)"
    )
    parser.add_argument(
        "-s", "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility"
    )
    parser.add_argument(
        "-i", "--impl",
        type=str,
        default="v1",
        choices=["v1", "v2", "v3", "v4"],
        help="Implementation to test: v1, v2, v3, or v4 (default: v1)"
    )
    parser.add_argument(
        "-g", "--generator",
        type=str,
        default="random",
        choices=["random", "structured", "expression", "mixed"],
        help="Generator type: 'random', 'structured', 'expression', or 'mixed' (default: random)"
    )

    args = parser.parse_args()

    run_fuzzer(
        num_tests=args.num_tests,
        seed=args.seed,
        impl=args.impl,
        generator=args.generator
    )
