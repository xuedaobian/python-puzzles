from marshal import load
from opcode import HAVE_ARGUMENT
from string import printable

from typing import Tuple, List
from types import CodeType


def load_bytecode(filename: str) -> Tuple[bytes, CodeType]:
    """
    Loads and returns the header bytes and bytecode CodeType object of a given
    pyc or pyo file. If the filename given is not a valid pyc or pyo file, a
    ValueError exception is thrown.
    """
    with open(filename, "rb") as bytecode_file:
        header = bytecode_file.read(16)
        bytecode = load(bytecode_file)

    return header, bytecode


def parse_units(bytecode: CodeType) -> Tuple[List[int], List[int]]:
    """
    Returns a list of opcodes and corresponding arguments from the bytecode of
    a given CodeType object. Will throw an IndexError if there is an uneven
    number of bytes in any of the given bytecode.
    """
    code = bytecode.co_code
    opcodes = [code[i] for i in range(0, len(code), 2)]
    arguments = [code[i] for i in range(1, len(code), 2)]

    for const in filter(lambda c: isinstance(c, CodeType), bytecode.co_consts):
        const_opcodes, const_arguments = parse_units(const)

        opcodes.extend(const_opcodes)
        arguments.extend(const_arguments)

    return opcodes, arguments


def no_arguments(opcodes: List[int], arguments: List[int]) -> int:
    """
    Yields the argument values for all opcodes which do not require arguments
    (opcodes < opcode.HAVE_ARGUMENT).
    """
    for opcode, argument in zip(opcodes, arguments):
        if opcode < HAVE_ARGUMENT:
            yield argument


def count_suspicious(opcodes: List[int], arguments: List[int]) -> int:
    """
    Counts the number of opcoe-argument pairs where the opcode indicates no
    argument is required but one is given regardless. In the absence of
    intentional tampering, no such pairs should exist.
    """
    count = 0
    for argument in no_arguments(opcodes, arguments):
        if argument != 0:
            count += 1

    return count


def recover_printable(opcodes: List[int], arguments: List[int]) -> str:
    """
    Returns a string comprised of all arguments bytes which are utf-8 decodable
    and are provided to opcodes which do not require arguments.
    """
    return bytes(filter(
        lambda b: chr(b) in printable,
        no_arguments(opcodes, arguments)
    )).decode()


def recover_bytes(opcodes: List[int], arguments: List[int]) -> bytes:
    """
    Returns all argument bytes bytes provided to opcodes which do not require
    arguments.
    """
    return bytes(no_arguments(opcodes, arguments))


def main(argv: List[str]):
    try:
        filename = argv[1]
    except IndexError:
        print("ERROR: Not enough command line arguments >_<")
        exit()

    try:
        _header, bytecode = load_bytecode(filename)
    except ValueError:
        print("ERROR: Not a valid python bytecode file >_<")
        exit()

    try:
        opcodes, arguments = parse_units(bytecode)
    except IndexError:
        print("ERROR: Invalid bytecode encoding >_<")
        exit()

    units = len(opcodes) // 2

    suspicious = count_suspicious(opcodes, arguments)

    if suspicious:
        print(f"{suspicious}/{units} opcode arguments are suspicious -_-\n")

        payload_printable = recover_printable(opcodes, arguments)
        if payload_printable:
            print(f"Printable dead zone bytes: {payload_printable}\n")

        print(f"All dead zone bytes: {recover_bytes(opcodes, arguments)}")

    print("No suspicious opcode arguments found ^_^")


if __name__ == "__main__":
    from sys import argv

    main(argv)