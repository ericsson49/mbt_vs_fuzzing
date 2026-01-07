"""Expression tree ADT: constants, sums, and products."""
from __future__ import annotations
from dataclasses import dataclass
from random import Random
from sloppy_vm_spec import serialize_program, Instruction
from typing import Union, List, Callable


UINT32_MAX = 0xFFFFFFFF


def _default_const_generator(rng: Random) -> int:
    """Default constant generator: random 32-bit unsigned integer."""
    return rng.randint(0, UINT32_MAX)


@dataclass(frozen=True)
class Const:
    """A 32-bit unsigned constant."""
    value: int

    def __post_init__(self):
        if not isinstance(self.value, int):
            raise TypeError(f"Const value must be int, got {type(self.value)}")
        if self.value < 0 or self.value > UINT32_MAX:
            raise ValueError(f"Const value must be in [0, {UINT32_MAX}], got {self.value}")


@dataclass(frozen=True)
class Add:
    """Sum of two expressions."""
    left: Expr
    right: Expr


@dataclass(frozen=True)
class Mul:
    """Product of two expressions."""
    left: Expr
    right: Expr


@dataclass(frozen=True)
class Byte:
    """Extract a byte from a 64-bit value at specified index."""
    value: Expr
    index: Expr


# Expression is a union of the four variants
Expr = Union[Const, Add, Mul, Byte]


# =============================================================================
# Compilation (Expr -> SloppyVM Bytecode)
# =============================================================================

def compile_expr_to_instructions(expr: Expr) -> List[Instruction]:
    """
    Compile an expression tree to a list of SloppyVM instructions.

    Uses post-order traversal: compile left operand, compile right operand,
    then emit the operation. For constants, emit PUSH4 directly.

    Examples:
        Const(5)           -> [PUSH4(5)]
        Add(Const(3), Const(4)) -> [PUSH4(3), PUSH4(4), ADD()]
        Mul(Const(2), Add(Const(3), Const(4))) -> [PUSH4(2), PUSH4(3), PUSH4(4), ADD(), MUL()]
        Byte(Const(0x123456789ABCDEF0), Const(1)) -> [PUSH4(...), PUSH4(1), BYTE()]
    """
    from sloppy_vm_spec import PUSH4, ADD, MUL, BYTE

    match expr:
        case Const(value=val):
            return [PUSH4(val)]
        case Add(left=left, right=right):
            return compile_expr_to_instructions(left) + compile_expr_to_instructions(right) + [ADD()]
        case Mul(left=left, right=right):
            return compile_expr_to_instructions(left) + compile_expr_to_instructions(right) + [MUL()]
        case Byte(value=value, index=index):
            return compile_expr_to_instructions(value) + compile_expr_to_instructions(index) + [BYTE()]
        case _:
            raise ValueError(f"Unknown expression type: {expr}")


def compile_expr(expr: Expr) -> bytes:
    """Compile an expression tree to SloppyVM bytecode."""
    return serialize_program(compile_expr_to_instructions(expr))


# =============================================================================
# Random Expression Generation
# =============================================================================


def random_expr(rng: Random, max_depth: int = 3, const_generator: Callable[[Random], int] = _default_const_generator) -> Expr:
    """
    Generate a random expression tree.

    At each level, randomly chooses between:
    - Const (40% probability)
    - Add (25% probability)
    - Mul (25% probability)
    - Byte (10% probability)

    When max_depth reaches 0, only generates Const to ensure termination.

    Args:
        rng: Random number generator (use Random(seed) for reproducibility)
        max_depth: Maximum depth of the expression tree
        const_generator: Callable that generates constant values.
                         Defaults to random 32-bit unsigned integers.

    Returns:
        A randomly generated expression
    """
    if max_depth <= 0:
        return Const(const_generator(rng))

    choice = rng.random()

    if choice < 0.4:
        # Generate a constant
        return Const(const_generator(rng))
    elif choice < 0.65:
        # Generate addition
        return Add(
            random_expr(rng, max_depth - 1, const_generator),
            random_expr(rng, max_depth - 1, const_generator)
        )
    elif choice < 0.9:
        # Generate multiplication
        return Mul(
            random_expr(rng, max_depth - 1, const_generator),
            random_expr(rng, max_depth - 1, const_generator)
        )
    else:
        # Generate byte extraction
        return Byte(
            random_expr(rng, max_depth - 1, const_generator),
            random_expr(rng, max_depth - 1, const_generator)
        )
