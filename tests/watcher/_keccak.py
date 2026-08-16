"""A standalone Keccak-256, used to verify one constant and nothing else.

Why this exists instead of a dependency: `watcher/detect/erc20.py` hardcodes
`TRANSFER_TOPIC0` and deliberately has no hashing library, because pulling one in
would also put a second address-producing code path into the repository —
addresses are produced by the deriver, from the xpub, and by nobody else (TZ
5.8/T1). But a hardcoded hash that nothing verifies is a hardcoded hash that is
wrong, and a wrong `topics[0]` is the worst failure this process can have: the
filter matches nothing, no errors are raised, no payments are seen, and the
watcher looks perfectly healthy while every customer's money goes undetected.

So the check has to run, and it has to be *independent* — verifying a value
against the same library that produced it proves only self-consistency. A gated
dev dependency would let the check skip on the machine where it matters. Sixty
lines of Keccak here mean it always runs and shares no code with anything.

This is the FIPS-202 Keccak-f[1600] permutation with the original Keccak padding
(0x01), which is what Ethereum uses — not SHA3-256's 0x06. The known-answer test
at the bottom of this module is what proves the implementation itself, so a bug
here fails loudly rather than quietly agreeing with a wrong constant.
"""

from __future__ import annotations

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_ROTATION_OFFSETS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_MASK64 = (1 << 64) - 1
_RATE_BYTES = 136  # 1600 bits state - 512 bits capacity, for a 256-bit digest


def _rotl64(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(state: list[list[int]]) -> list[list[int]]:
    for rnd in range(24):
        # theta
        column_parity = [
            state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)
        ]
        delta = [
            column_parity[(x - 1) % 5] ^ _rotl64(column_parity[(x + 1) % 5], 1) for x in range(5)
        ]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= delta[x]

        # rho + pi
        rotated = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                rotated[y][(2 * x + 3 * y) % 5] = _rotl64(state[x][y], _ROTATION_OFFSETS[x][y])

        # chi
        for x in range(5):
            for y in range(5):
                state[x][y] = rotated[x][y] ^ (
                    (~rotated[(x + 1) % 5][y] & _MASK64) & rotated[(x + 2) % 5][y]
                )

        # iota
        state[0][0] ^= _ROUND_CONSTANTS[rnd]
    return state


def keccak256(data: bytes) -> bytes:
    """Ethereum's Keccak-256 (0x01 padding, not SHA3's 0x06)."""
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _RATE_BYTES != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80

    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), _RATE_BYTES):
        block = padded[offset : offset + _RATE_BYTES]
        for lane in range(_RATE_BYTES // 8):
            value = int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
            state[lane % 5][lane // 5] ^= value
        state = _keccak_f1600(state)

    digest = bytearray()
    for lane in range(4):  # 4 lanes x 8 bytes = 32 bytes
        digest += state[lane % 5][lane // 5].to_bytes(8, "little")
    return bytes(digest)


#: Published Keccak-256 of the empty string. Checked by `test_erc20.py` before
#: the implementation is trusted with anything else.
KECCAK256_OF_EMPTY = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
