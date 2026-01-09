from dataclasses import dataclass
from typing import Union, List, Optional, Tuple

# =============================================================================
# Constants
# =============================================================================

UINT64_MAX = (1 << 64) - 1

# Opcodes
OP_PUSH4 = 0x01
OP_ADD   = 0x02
OP_MUL   = 0x03
OP_BYTE  = 0x04

# =============================================================================
# Instruction ADT
# =============================================================================

@dataclass(frozen=True)
class PUSH4:
    """Push a 4-byte (32-bit) value onto the stack."""
    value: int
    
    def __post_init__(self):
        if not (0 <= self.value <= 0xFFFFFFFF):
            raise ValueError(f"PUSH4 value must be 0-0xFFFFFFFF, got {self.value}")

@dataclass(frozen=True)
class ADD:
    """Pop two values, push their sum (mod 2^64)."""
    pass

@dataclass(frozen=True)
class MUL:
    """Pop two values, push their product (mod 2^64)."""
    pass

@dataclass(frozen=True)
class BYTE:
    """Extract byte from value at given index."""
    pass

Instruction = Union[PUSH4, ADD, MUL, BYTE]

# =============================================================================
# Serialization (Instructions -> Bytes)
# =============================================================================

def serialize_instruction(instr: Instruction) -> bytes:
    """
    Serialize a single instruction to bytes.
    
    Format:
        PUSH4: [0x01] [value: 4 bytes big-endian]  (5 bytes total)
        ADD:   [0x02]                               (1 byte)
        MUL:   [0x03]                               (1 byte)
        BYTE:  [0x04]                               (1 byte)
    """
    match instr:
        case PUSH4(value=val):
            return bytes([OP_PUSH4]) + val.to_bytes(4, 'big')
        case ADD():
            return bytes([OP_ADD])
        case MUL():
            return bytes([OP_MUL])
        case BYTE():
            return bytes([OP_BYTE])
        case _:
            raise ValueError(f"Unknown instruction: {instr}")


def serialize_program(instructions: List[Instruction]) -> bytes:
    """Serialize a list of instructions to bytecode."""
    return b''.join(serialize_instruction(instr) for instr in instructions)

# =============================================================================
# Exceptions
# =============================================================================

class SloppyVMException(Exception):
    """Base exception for all SloppyVM errors."""
    pass


class InvalidInstruction(SloppyVMException):
    """Raised when bytecode cannot be deserialized or an unknown opcode is encountered during execution."""
    pass


class StackUnderflow(SloppyVMException):
    """Raised when stack underflow occurs (popping from empty stack)."""
    pass


# =============================================================================
# Deserialization (Bytes -> Instructions)
# =============================================================================


def deserialize_instruction(data: bytes, offset: int = 0) -> Tuple[Instruction, int]:
    """
    Deserialize a single instruction from bytes.

    Args:
        data: Bytecode buffer
        offset: Starting position in buffer

    Returns:
        Tuple of (instruction, new_offset)

    Raises:
        InvalidInstruction: If bytecode is invalid or truncated
    """
    if offset >= len(data):
        raise InvalidInstruction(
            f"Cannot deserialize from empty or truncated bytecode (offset {offset}, length {len(data)})"
        )

    opcode = data[offset]

    match opcode:
        case _ if opcode == OP_PUSH4:
            if offset + 5 > len(data):
                raise InvalidInstruction(
                    f"Truncated PUSH4 at offset {offset}: need 5 bytes, have {len(data) - offset}"
                )
            value = int.from_bytes(data[offset + 1:offset + 5], 'big')
            return PUSH4(value), offset + 5

        case _ if opcode == OP_ADD:
            return ADD(), offset + 1

        case _ if opcode == OP_MUL:
            return MUL(), offset + 1

        case _ if opcode == OP_BYTE:
            return BYTE(), offset + 1
        
        case _:
            raise InvalidInstruction(f"Unknown opcode 0x{opcode:02X} at offset {offset}")


def deserialize_program(data: bytes) -> List[Instruction]:
    """
    Deserialize bytecode into a list of instructions.

    Args:
        data: Bytecode buffer

    Returns:
        List of instructions

    Raises:
        InvalidInstruction: If bytecode is invalid
    """
    instructions = []
    offset = 0
    
    while offset < len(data):
        instr, offset = deserialize_instruction(data, offset)
        instructions.append(instr)
    
    return instructions

# =============================================================================
# VM State and Execution (unchanged from before)
# =============================================================================

@dataclass
class VMState:
    stack: List[int]
    
    def __post_init__(self):
        for i, val in enumerate(self.stack):
            if not (0 <= val <= UINT64_MAX):
                raise ValueError(f"Stack value at {i} out of uint64 range: {val}")
    
    def copy(self) -> 'VMState':
        return VMState(stack=self.stack.copy())


def execute(state: VMState, instruction: Instruction) -> VMState:
    new_state = state.copy()
    stack = new_state.stack

    match instruction:
        case PUSH4(value=val):
            stack.append(val)
            return new_state

        case ADD():
            if len(stack) < 2:
                raise StackUnderflow("ADD requires 2 stack elements")
            a = stack.pop()
            b = stack.pop()
            stack.append((a + b) & UINT64_MAX)
            return new_state

        case MUL():
            if len(stack) < 2:
                raise StackUnderflow("MUL requires 2 stack elements")
            a = stack.pop()
            b = stack.pop()
            stack.append((a * b) & UINT64_MAX)
            return new_state

        case BYTE():
            if len(stack) < 2:
                raise StackUnderflow("BYTE requires 2 stack elements")
            i = stack.pop()
            x = stack.pop()
            if i >= 8:
                stack.append(0)
            else:
                x_bytes = x.to_bytes(8, 'big')
                stack.append(x_bytes[i])
            return new_state

        case _:
            raise InvalidInstruction(f"Unknown instruction type: {instruction}")


def execute_program(instructions: List[Instruction], initial_stack: Optional[List[int]] = None) -> VMState:
    state = VMState(stack=initial_stack or [])
    for instr in instructions:
        state = execute(state, instr)
    return state


def execute_bytecode(bytecode: bytes, initial_stack: Optional[List[int]] = None) -> VMState:
    """Convenience function to execute bytecode directly."""
    instructions = deserialize_program(bytecode)
    return execute_program(instructions, initial_stack)

