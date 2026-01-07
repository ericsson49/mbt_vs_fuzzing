"""
SloppyVM Implementation v4

This version fixes all known bugs from v1/v2/v3:
- Fixed: Missing modulo masking for overflow in ADD/MUL
- Fixed: Incorrect BYTE indexing (now uses `(7-i) * 8` for big-endian)
- Fixed: Wrong stack pop order for BYTE
- Fixed: Wrong bound check (now uses `i >= 8` instead of `i >= 7`)
"""

from typing import List, Optional

from sloppy_vm_spec import (
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
        StackUnderflow: On stack underflow
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
            # FIXED: Added modulo masking for overflow
            stack.append((a + b) & UINT64_MAX)
            offset += 1

        elif opcode == OP_MUL:
            if len(stack) < 2:
                raise StackUnderflow("MUL requires 2 stack elements")
            a = stack.pop()
            b = stack.pop()
            # FIXED: Added modulo masking for overflow
            stack.append((a * b) & UINT64_MAX)
            offset += 1

        elif opcode == OP_BYTE:
            if len(stack) < 2:
                raise StackUnderflow("BYTE requires 2 stack elements")
            # FIXED: wrong stack pop order
            i = stack.pop()
            x = stack.pop()
            # FIXED: wrong bound check (was i >= 7, now i >= 8)
            if i >= 8:
                stack.append(0)
            else:
                # FIXED: Use (7-i) for big-endian indexing (0=MSB, 7=LSB)
                shift = (7 - i) * 8
                result = (x >> shift) & 0xFF
                stack.append(result)
            offset += 1

        else:
            raise InvalidInstruction(f"Unknown opcode: 0x{opcode:02X} at offset {offset}")

    return stack
