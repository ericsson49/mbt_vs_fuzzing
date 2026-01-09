"""
Simple fuzzer for SloppyVM - compares buggy implementations against spec.

Generates completely random byte sequences and compares results from:
- Dynamically discovered sloppy_vm_impl_v*.py implementations
- sloppy_vm_spec.py (reference implementation)

Implementations are auto-discovered at runtime by searching for files
matching the pattern 'sloppy_vm_impl_v*.py' in the same directory as
this script. Each implementation must provide a callable execute(bytecode)
function that returns List[int].
"""

from dataclasses import dataclass
from enum import Enum
import random
from typing import List, Optional, Callable

from sloppyvm.spec import (
    deserialize_program, execute_program, SloppyVMException, InvalidInstruction,
    OP_PUSH4, OP_ADD, OP_MUL, OP_BYTE
)
from .expression import random_expr, compile_expr, UINT32_MAX
from sloppyvm.registry import get_available_versions, get_implementation


# =============================================================================
# Configuration Constants
# =============================================================================

# Structure-aware generation probabilities
PROB_PUSH4 = 0.45
PROB_ADD = 0.20
PROB_MUL = 0.17
PROB_BYTE = 0.15
PROB_INVALID_OPCODE = 0.03

PROB_TRUNCATED_PUSH4 = 0.05

# Mixed strategy probabilities (equal weight)
PROB_RANDOM_STRATEGY = 0.25
PROB_STRUCTURED_STRATEGY = 0.25
PROB_EXPRESSION_DEFAULT = 0.25
PROB_EXPRESSION_FULL_RANGE = 0.25


@dataclass
class GeneratorConfig:
    """Configuration for bytecode generators."""
    max_length: int = 20              # For random generator
    max_instructions: int = 10        # For structured generator
    max_depth: int = 3                # For expression generator


DEFAULT_CONFIG = GeneratorConfig()


# =============================================================================
# Instruction Selection
# =============================================================================

class InstructionChoice(Enum):
    """Enum for instruction types in structure-aware generation."""
    PUSH4 = "push4"
    ADD = "add"
    MUL = "mul"
    BYTE = "byte"
    INVALID = "invalid"


def choose_instruction() -> InstructionChoice:
    """Choose instruction type based on configured probabilities."""
    weights = [
        (InstructionChoice.PUSH4, int(PROB_PUSH4 * 100)),
        (InstructionChoice.ADD, int(PROB_ADD * 100)),
        (InstructionChoice.MUL, int(PROB_MUL * 100)),
        (InstructionChoice.BYTE, int(PROB_BYTE * 100)),
        (InstructionChoice.INVALID, int(PROB_INVALID_OPCODE * 100)),
    ]
    choices, probs = zip(*weights)
    return random.choices(choices, weights=probs)[0]


# =============================================================================
# Bytecode Generators
# =============================================================================

def generate_random_bytes(max_length: int = DEFAULT_CONFIG.max_length) -> bytes:
    """Generate completely random bytes - no structure consideration."""
    length = random.randint(1, max_length)
    return bytes(random.randint(0, 255) for _ in range(length))


def generate_structure_aware_bytecode(max_instructions: int = DEFAULT_CONFIG.max_instructions) -> bytes:
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
    instructions = []
    num_instructions = random.randint(1, max_instructions)

    for _ in range(num_instructions):
        instruction_type = choose_instruction()

        if instruction_type == InstructionChoice.PUSH4:
            value = random.randint(0, 0xFFFFFFFF)
            # Small chance of generating truncated PUSH4 (invalid bytecode)
            if random.random() < PROB_TRUNCATED_PUSH4:
                value_bytes = value.to_bytes(4, 'big')
                truncate_to = random.randint(1, 3)
                instructions.append(bytes([OP_PUSH4]) + value_bytes[:truncate_to])
                break  # Stop generating after truncating
            else:
                instructions.append(bytes([OP_PUSH4]) + value.to_bytes(4, 'big'))

        elif instruction_type == InstructionChoice.ADD:
            instructions.append(bytes([OP_ADD]))

        elif instruction_type == InstructionChoice.MUL:
            instructions.append(bytes([OP_MUL]))

        elif instruction_type == InstructionChoice.BYTE:
            instructions.append(bytes([OP_BYTE]))

        elif instruction_type == InstructionChoice.INVALID:
            invalid_opcode = random.choice([0x00] + list(range(0x05, 0x100)))
            instructions.append(bytes([invalid_opcode]))
            break  # Stop after invalid opcode

    return b''.join(instructions)


def generate_expression_bytecode(
    max_depth: int = DEFAULT_CONFIG.max_depth,
    max_value: Optional[int] = None
) -> bytes:
    """
    Generate bytecode using expression trees.

    Creates random expression trees (Const, Add, Mul, Byte) and compiles them to
    valid SloppyVM bytecode. This guarantees syntactically valid bytecode
    that will execute successfully (no stack underflow or invalid opcodes).

    Args:
        max_depth: Maximum depth of the expression tree
        max_value: Maximum value for random constants. If None, uses default list
                   [0-9, UINT32_MAX]. Otherwise, uses random.randint(0, max_value).

    Returns:
        Valid bytecode for a SloppyVM program
    """
    if max_value is None:
        # Default behavior: sample from specific values including edge cases
        const_values = [*range(0, 10), UINT32_MAX]
        def const_generator() -> int:
            return random.choice(const_values)
    else:
        # Generate random values in range [0, max_value]
        def const_generator() -> int:
            return random.randint(0, max_value)

    expr = random_expr(max_depth=max_depth, const_generator=const_generator)
    return compile_expr(expr)


def generate_mixed_strategy_bytecode(max_instructions: int = DEFAULT_CONFIG.max_instructions) -> bytes:
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

    if strategy_roll < PROB_RANDOM_STRATEGY:
        return generate_random_bytes()
    elif strategy_roll < PROB_RANDOM_STRATEGY + PROB_STRUCTURED_STRATEGY:
        return generate_structure_aware_bytecode(max_instructions=max_instructions)
    elif strategy_roll < PROB_RANDOM_STRATEGY + PROB_STRUCTURED_STRATEGY + PROB_EXPRESSION_DEFAULT:
        return generate_expression_bytecode(max_depth=DEFAULT_CONFIG.max_depth, max_value=None)
    else:
        return generate_expression_bytecode(max_depth=DEFAULT_CONFIG.max_depth, max_value=UINT32_MAX)


# Generator registry for dispatch
GENERATORS: dict[str, Callable[[], bytes]] = {
    "random": generate_random_bytes,
    "structured": generate_structure_aware_bytecode,
    "expression": generate_expression_bytecode,
    "mixed": generate_mixed_strategy_bytecode,
}


# =============================================================================
# Execution Results
# =============================================================================

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
    """Execute bytecode with reference implementation and return result."""
    try:
        instructions = deserialize_program(bytecode)
        result = execute_program(instructions)
        return Success(result.stack)
    except InvalidInstruction:
        return ExceptionThrown("invalid bytecode")
    except SloppyVMException as e:
        return ExceptionThrown(repr(e))


def execute_with_implementation(bytecode: bytes, impl_func: Callable[[bytes], List[int]]) -> ExecutionResult:
    """Execute bytecode with implementation under test and return result."""
    try:
        result = impl_func(bytecode)
        return Success(result)
    except SloppyVMException as e:
        return ExceptionThrown(repr(e))
    except Exception as e:
        return Crash(f"implementation raised exception: {repr(e)}")


def compare_results(expected: ExecutionResult, actual: ExecutionResult) -> bool:
    """
    Compare execution results for equivalence.

    Returns True if results match, considering:
    - Crashes match any crash (regardless of message)
    - Exceptions match any exception (regardless of message)
    - Success only matches with identical stack values
    """
    return (
        type(expected) == type(actual) and
        (not isinstance(expected, Success) or expected == actual)
    )


# =============================================================================
# Statistics Tracking
# =============================================================================

@dataclass
class FuzzingStatistics:
    """Tracks fuzzing run statistics."""
    total_tests: int = 0
    bugs_found: int = 0
    crashes: int = 0
    invalid_bytecodes: int = 0

    @property
    def valid_tests(self) -> int:
        return self.total_tests - self.invalid_bytecodes

    @property
    def correct_tests(self) -> int:
        return self.total_tests - self.bugs_found

    @property
    def bug_rate(self) -> float:
        return (self.bugs_found / self.total_tests * 100) if self.total_tests > 0 else 0.0

    def record_test(self, spec_result: ExecutionResult, impl_result: ExecutionResult, results_match: bool) -> None:
        """Record results of a single test."""
        self.total_tests += 1

        if isinstance(spec_result, ExceptionThrown) and spec_result.reason == "invalid bytecode":
            self.invalid_bytecodes += 1

        if isinstance(impl_result, Crash):
            self.crashes += 1

        if not results_match:
            self.bugs_found += 1

    def print_summary(self) -> None:
        """Print formatted summary of results."""
        print("\n" + "=" * 60)
        print("Fuzzer Summary")
        print("-" * 40)
        print(f"Total tests run:           {self.total_tests}")
        print(f"Invalid bytecodes:         {self.invalid_bytecodes}")
        print(f"Valid:                     {self.valid_tests}")
        print(f"Bugs found:                {self.bugs_found}")
        print(f"Impl crashes:              {self.crashes}")
        print(f"Correct:                   {self.correct_tests}")

        if self.bugs_found > 0:
            print(f"Bug detection rate:     {self.bug_rate:.1f}%")
        else:
            print("\nNo bugs detected!")


# =============================================================================
# Bug Reporting
# =============================================================================

def report_bug(test_num: int, bytecode: bytes, expected: ExecutionResult, actual: ExecutionResult) -> None:
    """Print detailed bug report."""
    print(f"\nTest {test_num}: Bug found")
    print(f"  Bytecode: {bytecode.hex()}")
    try:
        instructions = deserialize_program(bytecode)
        print(f"    {instructions}")
    except InvalidInstruction:
        pass
    print(f"  Expected: {expected}")
    print(f"  Actual:   {actual}")


def print_header(num_tests: int, impl: str, generator: str) -> None:
    """Print fuzzer run header."""
    print(f"SloppyVM Fuzzer - Running {num_tests} tests")
    print(f"Testing: {impl}")
    print(f"Generator: {generator}")
    print("=" * 60)


# =============================================================================
# Fuzzer Main Logic
# =============================================================================

def run_single_test(
    bytecode: bytes,
    spec_func: Callable[[bytes], ExecutionResult],
    impl_func: Callable[[bytes], List[int]]
) -> tuple[ExecutionResult, ExecutionResult, bool]:
    """
    Run a single fuzzing test case.

    Args:
        bytecode: The bytecode to test
        spec_func: Function to execute with reference implementation
        impl_func: Function to execute with implementation under test

    Returns:
        Tuple of (spec_result, impl_result, results_match)
    """
    spec_result = spec_func(bytecode)
    impl_result = execute_with_implementation(bytecode, impl_func)
    matches = compare_results(spec_result, impl_result)
    return spec_result, impl_result, matches


def run_fuzzer(
    num_tests: int = 1000,
    seed: Optional[int] = None,
    impl: str = "v1",
    generator: str = "random"
) -> FuzzingStatistics:
    """
    Run the fuzzer for a specified number of tests.

    Args:
        num_tests: Number of random test cases to generate
        seed: Random seed for reproducibility
        impl: Which implementation to test (auto-discovered from sloppy_vm_impl_v*.py)
        generator: Generator type: "random", "structured", "expression", or "mixed"

    Returns:
        FuzzingStatistics object with results
    """
    if seed is not None:
        random.seed(seed)

    # Select implementation and generator
    impl_func = get_implementation(impl).execute
    generator_func = GENERATORS.get(generator, generate_random_bytes)

    # Initialize statistics
    stats = FuzzingStatistics()

    # Print header
    print_header(num_tests, impl, generator)

    # Run tests
    for i in range(num_tests):
        bytecode = generator_func()
        spec_result, impl_result, matches = run_single_test(
            bytecode, execute_with_spec, impl_func
        )

        stats.record_test(spec_result, impl_result, matches)

        if not matches:
            report_bug(i + 1, bytecode, spec_result, impl_result)

    # Print summary
    stats.print_summary()
    return stats


# =============================================================================
# CLI Entry Point
# =============================================================================

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
        default=get_available_versions()[0],
        choices=get_available_versions(),
        help=f"Implementation to test. Available: {', '.join(get_available_versions())} (default: %(default)s)"
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
