"""
SloppyVM Implementation - Initial Deliberately Incorrect Version

This is a buggy implementation meant for testing MBT vs fuzzing techniques.
Known issues:
- No stack underflow checking (will crash/produce incorrect results)
- No invalid instruction checking (will crash on unknown opcodes)
- Various subtle bugs in instruction implementations
"""

from typing import List, Optional

# Import constants from spec to ensure consistency
from sloppy_vm_spec import UINT64_MAX, OP_PUSH4, OP_ADD, OP_MUL, OP_BYTE


def execute(bytecode: bytes) -> Optional[List[int]]:
    """
    Execute bytecode and return the final stack state.

    Args:
        bytecode: Bytecode buffer to execute

    Returns:
        List of integers representing the stack, or None on fatal error
        (Note: this version has minimal error checking)
    """
    stack: List[int] = []
    offset = 0

    while offset < len(bytecode):
        opcode = bytecode[offset]

        if opcode == OP_PUSH4:
            # BUG: Using little-endian instead of big-endian
            # BUG: No bounds checking for buffer size
            value = int.from_bytes(bytecode[offset + 1:offset + 5], 'little')
            stack.append(value)
            offset += 5

        elif opcode == OP_ADD:
            # BUG: No stack underflow checking
            a = stack.pop()
            b = stack.pop()
            # BUG: Missing modulo masking for overflow
            stack.append(a + b)
            offset += 1

        elif opcode == OP_MUL:
            # BUG: No stack underflow checking
            a = stack.pop()
            b = stack.pop()
            # BUG: Missing modulo masking for overflow
            stack.append(a * b)
            offset += 1

        elif opcode == OP_BYTE:
            # BUG: No stack underflow checking
            # BUG: wrong stack pop order
            x = stack.pop()
            i = stack.pop()
            if i >= 8:
                stack.append(0)
            else:
                shift = i * 8  # BUG: should be (7-i) * 8
                result = (x >> shift) & 0xFF
                stack.append(result)
            offset += 1

        else:
            # BUG: Unknown opcodes will crash instead of raising error
            raise RuntimeError(f"Unknown opcode: 0x{opcode:02X}")

    return stack

