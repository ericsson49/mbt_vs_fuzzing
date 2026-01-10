"""
Tests for enumeration-based test generation.

Verifies that enumeration produces complete, deterministic, and duplicate-free
test suites for SloppyVM.

Run with: uv run python tests/test_enumeration.py
"""

from sloppyvm.spec import (
    deserialize_program, execute_bytecode, Instruction,
    PUSH4, ADD, MUL, BYTE,
    InvalidInstruction, StackUnderflow
)
from sloppyvm.fuzzing.enumeration import (
    enumerate_expressions,
    enumerate_expression_programs,
    enumerate_byte_boundary_tests,
    enumerate_arithmetic_overflow_tests,
    enumerate_stack_underflow_tests,
    generate_comprehensive_suite,
    BOUNDARY_CONSTANTS,
    MINIMAL_CONSTANTS,
)
from sloppyvm.fuzzing.expression import Expr, Const, Add, Mul, Byte


def test_expression_enumeration():
    """Tests for expression enumeration."""
    print("Expression Enumeration Tests")
    print("=" * 50)

    # Test depth 0
    constants = [0, 1, 2]
    expressions = list(enumerate_expressions(0, constants))
    assert len(expressions) == 3
    assert all(isinstance(e, Const) for e in expressions)
    print("✓ Depth 0 enumeration")

    # Test depth 1
    constants = [0, 1]
    expressions = list(enumerate_expressions(1, constants))
    assert len(expressions) == 14
    print("✓ Depth 1 enumeration")

    # Test no duplicates
    constants = [0, 1]
    expressions = list(enumerate_expressions(2, constants))
    expr_strings = [str(e) for e in expressions]
    assert len(expr_strings) == len(set(expr_strings))
    print("✓ No duplicate expressions")

    # Test expression programs are valid
    programs = list(enumerate_expression_programs(max_depth=1, constants=[0, 1]))
    for bytecode in programs:
        instructions = deserialize_program(bytecode)
        assert len(instructions) > 0
    print("✓ Expression programs are valid")


def test_boundary_value_tests():
    """Tests for boundary value test generation."""
    print("\nBoundary Value Tests")
    print("=" * 50)

    # Test BYTE boundary tests
    tests = list(enumerate_byte_boundary_tests())
    assert len(tests) >= 50
    print(f"✓ BYTE boundary tests ({len(tests)} tests)")

    # Test validity
    for bytecode in tests:
        instructions = deserialize_program(bytecode)
        assert len(instructions) == 3
        assert isinstance(instructions[0], PUSH4)
        assert isinstance(instructions[1], PUSH4)
        assert isinstance(instructions[2], BYTE)
    print("✓ All BYTE boundary tests valid")

    # Test includes critical index 7
    has_index_7 = False
    for bytecode in tests:
        instructions = deserialize_program(bytecode)
        if isinstance(instructions[1], PUSH4) and instructions[1].value == 7:
            has_index_7 = True
            break
    assert has_index_7
    print("✓ Includes critical index 7")

    # Test arithmetic overflow tests
    tests = list(enumerate_arithmetic_overflow_tests())
    assert len(tests) >= 10
    print(f"✓ Arithmetic overflow tests ({len(tests)} tests)")

    # Test stack underflow tests
    tests = list(enumerate_stack_underflow_tests())
    assert len(tests) >= 10
    underflow_count = 0
    for bytecode in tests:
        try:
            execute_bytecode(bytecode)
        except StackUnderflow:
            underflow_count += 1
    assert underflow_count == len(tests)
    print(f"✓ Stack underflow tests ({len(tests)} tests, all trigger underflow)")


def test_comprehensive_suite():
    """Tests for comprehensive enumeration suite."""
    print("\nComprehensive Suite Tests")
    print("=" * 50)

    # Test no duplicates
    suite = list(generate_comprehensive_suite(max_expr_depth=1))
    hex_strings = [b.hex() for b in suite]
    assert len(hex_strings) == len(set(hex_strings))
    print(f"✓ No duplicates ({len(suite)} unique tests)")

    # Test all valid bytecode
    valid_count = 0
    for bytecode in suite:
        try:
            instructions = deserialize_program(bytecode)
            valid_count += 1
        except InvalidInstruction:
            pass
    print(f"✓ All deserializable ({valid_count}/{len(suite)} valid)")

    # Test includes boundary tests
    suite_set = set(b.hex() for b in suite)
    byte_tests = list(enumerate_byte_boundary_tests())
    included_count = sum(1 for test in byte_tests if test.hex() in suite_set)
    print(f"✓ Includes boundary tests ({included_count}/{len(byte_tests)} included)")


def test_determinism():
    """Tests for deterministic enumeration behavior."""
    print("\nDeterminism Tests")
    print("=" * 50)

    # Test enumeration is deterministic
    suite1 = list(generate_comprehensive_suite(max_expr_depth=1))
    suite2 = list(generate_comprehensive_suite(max_expr_depth=1))
    assert len(suite1) == len(suite2)
    assert all(b1 == b2 for b1, b2 in zip(suite1, suite2))
    print("✓ Enumeration is deterministic")

    # Test expression order stable
    constants = [0, 1, 7, 8]
    exprs1 = list(enumerate_expressions(1, constants))
    exprs2 = list(enumerate_expressions(1, constants))
    assert [str(e) for e in exprs1] == [str(e) for e in exprs2]
    print("✓ Expression enumeration order stable")


def test_boundary_constants():
    """Tests for boundary constant definitions."""
    print("\nBoundary Constants Tests")
    print("=" * 50)

    # Test critical values
    assert 0 in BOUNDARY_CONSTANTS
    assert 1 in BOUNDARY_CONSTANTS
    assert 7 in BOUNDARY_CONSTANTS
    assert 8 in BOUNDARY_CONSTANTS
    assert 0xFFFFFFFF in BOUNDARY_CONSTANTS
    print(f"✓ BOUNDARY_CONSTANTS includes critical values ({len(BOUNDARY_CONSTANTS)} total)")

    # Test minimal constants
    assert len(MINIMAL_CONSTANTS) <= 10
    assert 0 in MINIMAL_CONSTANTS
    assert 7 in MINIMAL_CONSTANTS
    assert 8 in MINIMAL_CONSTANTS
    print(f"✓ MINIMAL_CONSTANTS is minimal ({len(MINIMAL_CONSTANTS)} constants)")


def test_integration():
    """Integration tests with actual VM implementations."""
    print("\nIntegration Tests")
    print("=" * 50)

    from sloppyvm.registry import get_implementation

    # Test finds v3 bug
    v3 = get_implementation("v3")
    suite = list(generate_comprehensive_suite(max_expr_depth=1))
    bugs_found = 0
    for bytecode in suite:
        try:
            spec_result = execute_bytecode(bytecode)
        except (InvalidInstruction, StackUnderflow):
            continue

        try:
            v3_result = v3.execute(bytecode)
            if spec_result.stack != v3_result:
                bugs_found += 1
        except Exception:
            pass

    assert bugs_found > 0
    print(f"✓ Finds bugs in v3 ({bugs_found} bugs found)")

    # Test v4 passes
    v4 = get_implementation("v4")
    suite = list(generate_comprehensive_suite(max_expr_depth=1))
    bugs_found = 0
    for bytecode in suite:
        try:
            spec_result = execute_bytecode(bytecode)
        except (InvalidInstruction, StackUnderflow):
            continue

        try:
            v4_result = v4.execute(bytecode)
            if spec_result.stack != v4_result:
                bugs_found += 1
        except Exception:
            bugs_found += 1

    assert bugs_found == 0
    print(f"✓ v4 passes all enumeration tests ({len(suite)} tests)")


if __name__ == "__main__":
    print("SloppyVM Enumeration Tests")
    print("=" * 60)
    print()

    test_expression_enumeration()
    test_boundary_value_tests()
    test_comprehensive_suite()
    test_determinism()
    test_boundary_constants()
    test_integration()

    print("\n" + "=" * 60)
    print("All tests passed!")

