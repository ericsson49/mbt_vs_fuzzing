"""
Test suite for SloppyVM.

Run with: uv run test_sloppy_vm.py
"""

from sloppy_vm_spec import (
    # Instructions
    PUSH4, ADD, MUL, BYTE, Instruction,
    # Serialization
    serialize_instruction, serialize_program,
    deserialize_instruction, deserialize_program,
    # Execution
    VMState, execute, execute_program, execute_bytecode,
    # Exceptions
    InvalidInstruction, StackUnderflow,
    # Utilities
    UINT64_MAX
)


def test_serialization():
    print("SloppyVM Serialization Tests")
    print("=" * 50)

    # Test individual instruction serialization
    assert serialize_instruction(PUSH4(0xDEADBEEF)) == bytes([0x01, 0xDE, 0xAD, 0xBE, 0xEF])
    assert serialize_instruction(ADD()) == bytes([0x02])
    assert serialize_instruction(MUL()) == bytes([0x03])
    assert serialize_instruction(BYTE()) == bytes([0x04])
    print("✓ Individual instruction serialization")

    # Test round-trip for single instructions
    for instr in [PUSH4(0), PUSH4(0xFFFFFFFF), PUSH4(0x12345678), ADD(), MUL(), BYTE()]:
        serialized = serialize_instruction(instr)
        deserialized, _ = deserialize_instruction(serialized)
        assert deserialized == instr, f"Round-trip failed for {instr}"
    print("✓ Single instruction round-trip")

    # Test program serialization
    program = [
        PUSH4(3),
        PUSH4(4),
        ADD(),
        PUSH4(5),
        MUL(),
    ]

    bytecode = serialize_program(program)
    expected = bytes([
        0x01, 0x00, 0x00, 0x00, 0x03,  # PUSH4 3
        0x01, 0x00, 0x00, 0x00, 0x04,  # PUSH4 4
        0x02,                           # ADD
        0x01, 0x00, 0x00, 0x00, 0x05,  # PUSH4 5
        0x03,                           # MUL
    ])
    assert bytecode == expected
    print("✓ Program serialization")

    # Test program round-trip
    deserialized_program = deserialize_program(bytecode)
    assert deserialized_program == program
    print("✓ Program round-trip")

    # Test execute_bytecode
    result = execute_bytecode(bytecode)
    assert result.stack == [35]
    print("✓ Execute bytecode: (3 + 4) * 5 = 35")

    # Test error handling
    try:
        deserialize_program(bytes([0xFF]))
        assert False, "Should have raised"
    except InvalidInstruction as e:
        assert "Unknown opcode" in str(e)
    print("✓ Unknown opcode error")

    try:
        deserialize_program(bytes([0x01, 0x00, 0x00]))  # Truncated PUSH4
        assert False, "Should have raised"
    except InvalidInstruction as e:
        assert "Truncated" in str(e)
    print("✓ Truncated instruction error")

    # Test hex representation
    print(f"\n✓ Bytecode hex: {bytecode.hex()}")

    print("=" * 50)
    print("All serialization tests passed!")


def test_sloppy_vm():
    """Test cases demonstrating SloppyVM behavior."""

    print("SloppyVM Test Suite (64-bit, Unbounded Stack)")
    print("=" * 50)

    # PUSH4
    result = execute(VMState(stack=[]), PUSH4(0xDEADBEEF))
    assert result.stack == [0xDEADBEEF]
    print("✓ PUSH4")

    # ADD
    result = execute(VMState(stack=[10, 20]), ADD())
    assert result.stack == [30]
    print("✓ ADD")

    # ADD overflow (modular 64-bit)
    result = execute(VMState(stack=[UINT64_MAX, 2]), ADD())
    assert result.stack == [1]
    print("✓ ADD modular overflow (64-bit)")

    # MUL
    result = execute(VMState(stack=[7, 6]), MUL())
    assert result.stack == [42]
    print("✓ MUL")

    # MUL overflow (modular 64-bit)
    result = execute(VMState(stack=[0xFFFFFFFFFFFFFFFF, 2]), MUL())
    assert result.stack == [0xFFFFFFFFFFFFFFFE]
    print("✓ MUL modular overflow (64-bit)")

    # BYTE - byte 0 (MSB of 64-bit value)
    value = 0xFF << (7 * 8)  # 0xFF00000000000000
    result = execute(VMState(stack=[value, 0]), BYTE())
    assert result.stack == [0xFF]
    print("✓ BYTE (MSB, index=0)")

    # BYTE - byte 7 (LSB of 64-bit value)
    result = execute(VMState(stack=[0xAB, 7]), BYTE())
    assert result.stack == [0xAB]
    print("✓ BYTE (LSB, index=7)")

    # BYTE - middle byte
    value = 0x00FF000000000000  # FF at byte index 1
    result = execute(VMState(stack=[value, 1]), BYTE())
    assert result.stack == [0xFF]
    print("✓ BYTE (middle, index=1)")

    # BYTE - out of range (index >= 8)
    result = execute(VMState(stack=[0xFFFFFFFFFFFFFFFF, 8]), BYTE())
    assert result.stack == [0]
    print("✓ BYTE (index >= 8 returns 0)")

    # Stack underflow
    try:
        execute(VMState(stack=[42]), ADD())
        assert False, "Should have raised StackUnderflow"
    except StackUnderflow:
        pass

    try:
        execute(VMState(stack=[]), MUL())
        assert False, "Should have raised StackUnderflow"
    except StackUnderflow:
        pass

    try:
        execute(VMState(stack=[1]), BYTE())
        assert False, "Should have raised StackUnderflow"
    except StackUnderflow:
        pass
    print("✓ Stack underflow detection")

    # Complex program: (3 + 4) * 5 = 35
    program = [PUSH4(3), PUSH4(4), ADD(), PUSH4(5), MUL()]
    result = execute_program(program)
    assert result.stack == [35]
    print("✓ Complex program: (3 + 4) * 5 = 35")

    # Extract byte from computed value
    # 0x12345678 -> byte 4 = 0x12, byte 5 = 0x34, byte 6 = 0x56, byte 7 = 0x78
    program = [PUSH4(0x12345678), PUSH4(7), BYTE()]
    result = execute_program(program)
    assert result.stack == [0x78]
    print("✓ BYTE extraction: byte 7 of 0x12345678 = 0x78")

    program = [PUSH4(0x12345678), PUSH4(4), BYTE()]
    result = execute_program(program)
    assert result.stack == [0x12]
    print("✓ BYTE extraction: byte 4 of 0x12345678 = 0x12")

    print("=" * 50)
    print("All tests passed!")


if __name__ == "__main__":
    test_serialization()
    test_sloppy_vm()
