"""
SloppyVM Implementation v2 - Handles Unknown Bytecodes and Stack Underflow

This version is similar to v1 but handles unknown opcodes and stack underflow with custom exceptions.
Known issues:
- Unknown bytecodes raise InvalidInstruction exception - IMPROVEMENT over v1
- Stack underflow raises StackUnderflow exception - IMPROVEMENT over v1
- Various subtle bugs in instruction implementations (same as v1):
  * Missing modulo masking on ADD/MUL (no 64-bit wrap)
  * Incorrect BYTE indexing (uses `i * 8` instead of `(7-i) * 8`)
"""

from typing import List, Optional

from sloppyvm.spec import (
    SloppyVMException, InvalidInstruction, StackUnderflow,
    UINT64_MAX, OP_PUSH4, OP_ADD, OP_MUL, OP_BYTE
)


def execute(bytecode: bytes) -> List[int]:
    """
    Execute bytecode and return the final stack state.

    Args:
        bytecode: Bytecode buffer to execute

    Returns:
        List of integers representing the stack

    Raises:
        InvalidInstruction: When an unknown opcode is encountered
        StackUnderflow: On stack underflow (IMPROVEMENT over v1)
    """
    stack: List[int] = []
    offset = 0

    while offset < len(bytecode):
        opcode = bytecode[offset]

        if opcode == OP_PUSH4:
            if offset + 5 > len(bytecode):
                raise InvalidInstruction(
                    f"Truncated PUSH4 at offset {offset}: need 5 bytes, have {len(bytecode) - offset}"
                )
            value = int.from_bytes(bytecode[offset + 1:offset + 5], 'big')
            stack.append(value)
            offset += 5

        elif opcode == OP_ADD:
            if len(stack) < 2:
                raise StackUnderflow("ADD requires 2 stack elements")
            a = stack.pop()
            b = stack.pop()
            # BUG: Missing modulo masking for overflow
            stack.append(a + b)
            offset += 1

        elif opcode == OP_MUL:
            if len(stack) < 2:
                raise StackUnderflow("MUL requires 2 stack elements")
            a = stack.pop()
            b = stack.pop()
            # BUG: Missing modulo masking for overflow
            stack.append(a * b)
            offset += 1

        elif opcode == OP_BYTE:
            if len(stack) < 2:
                raise StackUnderflow("BYTE requires 2 stack elements")
            # BUG: wrong stack pop order
            x = stack.pop()
            i = stack.pop()
            # BUG: wrong bound check
            if i >= 7:
                stack.append(0)
            else:
                shift = i * 8  # BUG: should be (7-i) * 8
                result = (x >> shift) & 0xFF
                stack.append(result)
            offset += 1

        else:
            # IMPROVEMENT: Raise custom exception instead of generic RuntimeError
            raise InvalidInstruction(f"Unknown opcode: 0x{opcode:02X} at offset {offset}")

    return stack
