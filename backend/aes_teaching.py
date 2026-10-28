# ============================================================
# AES-128 EDUCATIONAL / TEACHING IMPLEMENTATION
# ============================================================
#
# This implementation exposes intermediate AES states so that
# students can observe how AES transforms a 128-bit block.
#
# It is intended for EDUCATIONAL VISUALIZATION ONLY.
# Production encryption continues to use cryptography/AESGCM.
# ============================================================


S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,

    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]


RCON = [
    0x00,
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36
]


# ============================================================
# MATRIX CONVERSION
# ============================================================

def bytes_to_state(data):
    """
    AES stores the 16 input bytes column-by-column.
    """

    return [
        [data[row + 4 * col] for col in range(4)]
        for row in range(4)
    ]


def state_to_bytes(state):

    result = []

    for col in range(4):
        for row in range(4):
            result.append(state[row][col])

    return bytes(result)


def copy_state(state):

    return [
        row[:] for row in state
    ]


def state_hex(state):

    return [
        [f"{value:02X}" for value in row]
        for row in state
    ]


# ============================================================
# SUBBYTES
# ============================================================

def sub_bytes(state):

    return [
        [S_BOX[value] for value in row]
        for row in state
    ]


# ============================================================
# SHIFTROWS
# ============================================================

def shift_rows(state):

    result = copy_state(state)

    result[0] = state[0][:]
    result[1] = state[1][1:] + state[1][:1]
    result[2] = state[2][2:] + state[2][:2]
    result[3] = state[3][3:] + state[3][:3]

    return result


# ============================================================
# GALOIS FIELD ARITHMETIC
# ============================================================

def xtime(value):

    value <<= 1

    if value & 0x100:
        value ^= 0x11B

    return value & 0xFF


def multiply_by_2(value):
    return xtime(value)


def multiply_by_3(value):
    return xtime(value) ^ value


# ============================================================
# MIXCOLUMNS
# ============================================================

def mix_single_column(column):

    a0, a1, a2, a3 = column

    return [
        multiply_by_2(a0) ^ multiply_by_3(a1) ^ a2 ^ a3,
        a0 ^ multiply_by_2(a1) ^ multiply_by_3(a2) ^ a3,
        a0 ^ a1 ^ multiply_by_2(a2) ^ multiply_by_3(a3),
        multiply_by_3(a0) ^ a1 ^ a2 ^ multiply_by_2(a3)
    ]


def mix_columns(state):

    result = [
        [0] * 4 for _ in range(4)
    ]

    for col in range(4):

        column = [
            state[row][col]
            for row in range(4)
        ]

        mixed = mix_single_column(column)

        for row in range(4):
            result[row][col] = mixed[row]

    return result


# ============================================================
# ADDROUNDKEY
# ============================================================

def add_round_key(state, round_key):

    return [
        [
            state[row][col] ^ round_key[row][col]
            for col in range(4)
        ]
        for row in range(4)
    ]


# ============================================================
# AES-128 KEY EXPANSION
# ============================================================

def rot_word(word):

    return word[1:] + word[:1]


def sub_word(word):

    return [
        S_BOX[value]
        for value in word
    ]


def expand_key(key):

    if len(key) != 16:
        raise ValueError(
            "AES-128 requires exactly 16 key bytes"
        )

    # AES key expansion operates on 4-byte words.
    words = [
        list(key[i:i + 4])
        for i in range(0, 16, 4)
    ]

    for i in range(4, 44):

        temp = words[i - 1][:]

        if i % 4 == 0:

            temp = rot_word(temp)
            temp = sub_word(temp)

            temp[0] ^= RCON[i // 4]

        new_word = [
            words[i - 4][j] ^ temp[j]
            for j in range(4)
        ]

        words.append(new_word)

    round_keys = []

    for round_number in range(11):

        key_bytes = []

        for word in words[
            round_number * 4:
            round_number * 4 + 4
        ]:
            key_bytes.extend(word)

        round_keys.append(
            bytes_to_state(bytes(key_bytes))
        )

    return round_keys


# ============================================================
# STEP RECORDER
# ============================================================

def record_step(
    steps,
    round_number,
    operation,
    state,
    description,
    round_key=None
):

    item = {
        "step": len(steps),
        "round": round_number,
        "operation": operation,
        "state": state_hex(state),
        "description": description
    }

    if round_key is not None:
        item["round_key"] = state_hex(round_key)

    steps.append(item)


# ============================================================
# AES-128 ENCRYPTION WITH INTERMEDIATE STATES
# ============================================================

def encrypt_block_with_steps(
    plaintext,
    key
):

    if len(plaintext) != 16:
        raise ValueError(
            "Teaching mode requires exactly 16 plaintext bytes"
        )

    if len(key) != 16:
        raise ValueError(
            "AES-128 requires exactly 16 key bytes"
        )

    steps = []

    round_keys = expand_key(key)

    state = bytes_to_state(plaintext)

    record_step(
        steps,
        0,
        "Input",
        state,
        "The 16 plaintext bytes are arranged "
        "column-by-column into the AES state matrix."
    )

    # --------------------------------------------------------
    # INITIAL ROUND
    # --------------------------------------------------------

    state = add_round_key(
        state,
        round_keys[0]
    )

    record_step(
        steps,
        0,
        "AddRoundKey",
        state,
        "Initial AddRoundKey: the plaintext state "
        "is XORed with round key 0.",
        round_keys[0]
    )

    # --------------------------------------------------------
    # ROUNDS 1 TO 9
    # --------------------------------------------------------

    for round_number in range(1, 10):

        state = sub_bytes(state)

        record_step(
            steps,
            round_number,
            "SubBytes",
            state,
            "Each state byte is replaced using "
            "the AES S-box."
        )

        state = shift_rows(state)

        record_step(
            steps,
            round_number,
            "ShiftRows",
            state,
            "Rows 1, 2 and 3 are cyclically shifted "
            "left by 1, 2 and 3 positions."
        )

        state = mix_columns(state)

        record_step(
            steps,
            round_number,
            "MixColumns",
            state,
            "Each column is transformed using "
            "AES arithmetic in GF(2^8)."
        )

        state = add_round_key(
            state,
            round_keys[round_number]
        )

        record_step(
            steps,
            round_number,
            "AddRoundKey",
            state,
            "The state is XORed with this round's "
            "expanded AES key.",
            round_keys[round_number]
        )

    # --------------------------------------------------------
    # FINAL ROUND - ROUND 10
    # --------------------------------------------------------

    state = sub_bytes(state)

    record_step(
        steps,
        10,
        "SubBytes",
        state,
        "Final-round SubBytes."
    )

    state = shift_rows(state)

    record_step(
        steps,
        10,
        "ShiftRows",
        state,
        "Final-round ShiftRows."
    )

    # IMPORTANT:
    # AES final round has NO MixColumns.

    state = add_round_key(
        state,
        round_keys[10]
    )

    record_step(
        steps,
        10,
        "AddRoundKey",
        state,
        "Final AddRoundKey. AES encryption "
        "of the block is now complete.",
        round_keys[10]
    )

    ciphertext = state_to_bytes(state)

    return {
        "plaintext_hex": plaintext.hex().upper(),
        "key_hex": key.hex().upper(),
        "ciphertext_hex": ciphertext.hex().upper(),
        "total_steps": len(steps),
        "steps": steps
    }

# ============================================================
# PHASE 8 — INSTRUMENTED AES-128 KEY EXPANSION
# ============================================================

def expand_key_with_steps(key_bytes):

    if len(key_bytes) != 16:
        raise ValueError(
            "AES-128 key must contain exactly 16 bytes."
        )

    # --------------------------------------------------------
    # ORIGINAL KEY → W0, W1, W2, W3
    # --------------------------------------------------------

    words = []

    for i in range(4):

        word = list(
            key_bytes[
                4 * i:
                4 * i + 4
            ]
        )

        words.append(word)

    derivations = []

    # Record original words

    for i in range(4):

        derivations.append({
            "word_index": i,
            "word_name": f"W{i}",
            "type": "original_key",
            "result": "".join(
                f"{b:02X}"
                for b in words[i]
            ),
            "description":
                "Word taken directly from the original AES-128 key."
        })

    # --------------------------------------------------------
    # GENERATE W4 ... W43
    # --------------------------------------------------------

    for i in range(4, 44):

        previous_word = words[i - 1][:]
        four_back_word = words[i - 4][:]

        # ====================================================
        # SPECIAL WORD
        # i mod 4 == 0
        # ====================================================

        if i % 4 == 0:

            rotword_result = rot_word(
                previous_word[:]
            )

            subword_result = sub_word(
                rotword_result[:]
            )

            rcon_value = RCON[
                (i // 4)
            ]

            rcon_word = [
                rcon_value,
                0x00,
                0x00,
                0x00
            ]

            g_result = [
                subword_result[0] ^ rcon_word[0],
                subword_result[1] ^ rcon_word[1],
                subword_result[2] ^ rcon_word[2],
                subword_result[3] ^ rcon_word[3]
            ]

            new_word = [
                four_back_word[j]
                ^ g_result[j]
                for j in range(4)
            ]

            words.append(
                new_word
            )

            derivations.append({
                "word_index": i,
                "word_name": f"W{i}",
                "type": "core",
                "previous_word":
                    "".join(
                        f"{b:02X}"
                        for b in previous_word
                    ),
                "four_back_word":
                    "".join(
                        f"{b:02X}"
                        for b in four_back_word
                    ),
                "rotword":
                    "".join(
                        f"{b:02X}"
                        for b in rotword_result
                    ),
                "subword":
                    "".join(
                        f"{b:02X}"
                        for b in subword_result
                    ),
                "rcon":
                    "".join(
                        f"{b:02X}"
                        for b in rcon_word
                    ),
                "g_result":
                    "".join(
                        f"{b:02X}"
                        for b in g_result
                    ),
                "result":
                    "".join(
                        f"{b:02X}"
                        for b in new_word
                    ),
                "description":
                    (
                        f"W{i} uses the AES key-schedule core: "
                        f"RotWord → SubWord → Rcon → XOR with W{i - 4}."
                    )
            })

        # ====================================================
        # ORDINARY WORD
        # ====================================================

        else:

            new_word = [
                four_back_word[j]
                ^ previous_word[j]
                for j in range(4)
            ]

            words.append(
                new_word
            )

            derivations.append({
                "word_index": i,
                "word_name": f"W{i}",
                "type": "xor",
                "previous_word":
                    "".join(
                        f"{b:02X}"
                        for b in previous_word
                    ),
                "four_back_word":
                    "".join(
                        f"{b:02X}"
                        for b in four_back_word
                    ),
                "result":
                    "".join(
                        f"{b:02X}"
                        for b in new_word
                    ),
                "description":
                    (
                        f"W{i} = W{i - 4} XOR W{i - 1}"
                    )
            })

    # --------------------------------------------------------
    # BUILD 11 ROUND KEYS
    # --------------------------------------------------------

    round_keys = []

    for round_number in range(11):

        start = (
            round_number * 4
        )

        round_words = (
            words[start:start + 4]
        )

        key_hex = "".join(
            "".join(
                f"{byte:02X}"
                for byte in word
            )
            for word in round_words
        )

        # Matrix representation consistent with AES state
        # column-major display.

        flat_bytes = []

        for word in round_words:
            flat_bytes.extend(word)

        matrix = bytes_to_state(
            bytes(flat_bytes)
        )

        round_keys.append({
            "round": round_number,
            "words": [
                f"W{start}",
                f"W{start + 1}",
                f"W{start + 2}",
                f"W{start + 3}"
            ],
            "key_hex": key_hex,
            "matrix": state_hex(matrix)
        })

    # --------------------------------------------------------
    # RETURN COMPLETE EDUCATIONAL DATA
    # --------------------------------------------------------

    return {
        "key_hex": key_bytes.hex().upper(),
        "total_words": len(words),
        "total_round_keys": len(round_keys),
        "words": [
            {
                "index": i,
                "name": f"W{i}",
                "hex": "".join(
                    f"{byte:02X}"
                    for byte in word
                )
            }
            for i, word in enumerate(words)
        ],
        "derivations": derivations,
        "round_keys": round_keys
    }

# ============================================================
# PHASE 9 — AES-128 AVALANCHE ANALYSIS
# ============================================================

def state_matrix_to_bytes(state):
    """
    Convert the 4x4 hexadecimal state representation returned
    by the teaching engine back into AES column-major bytes.
    """

    output = []

    for column in range(4):
        for row in range(4):
            output.append(
                int(state[row][column], 16)
            )

    return bytes(output)


def hamming_distance_bytes(a, b):
    """
    Count differing bits between two equal-length byte strings.
    """

    if len(a) != len(b):
        raise ValueError(
            "Hamming-distance inputs must have equal length."
        )

    distance = 0

    for left, right in zip(a, b):
        distance += (
            left ^ right
        ).bit_count()

    return distance


def flip_bit(data, bit_index):
    """
    Flip one bit in a byte string.

    Bit numbering:
        0   = MSB of byte 0
        7   = LSB of byte 0
        8   = MSB of byte 1
        ...
        127 = LSB of byte 15
    """

    if len(data) != 16:
        raise ValueError(
            "AES-128 avalanche input must contain exactly 16 bytes."
        )

    if bit_index < 0 or bit_index > 127:
        raise ValueError(
            "Bit index must be between 0 and 127."
        )

    result = bytearray(data)

    byte_index = bit_index // 8
    bit_position = bit_index % 8

    mask = 1 << (
        7 - bit_position
    )

    result[byte_index] ^= mask

    return bytes(result)


def avalanche_analysis(
    plaintext_bytes,
    key_bytes,
    experiment_type,
    bit_index
):
    """
    Compare two complete AES-128 executions after changing
    exactly one plaintext bit or one key bit.
    """

    if len(plaintext_bytes) != 16:
        raise ValueError(
            "Plaintext must contain exactly 16 bytes."
        )

    if len(key_bytes) != 16:
        raise ValueError(
            "AES-128 key must contain exactly 16 bytes."
        )

    if experiment_type not in (
        "plaintext",
        "key"
    ):
        raise ValueError(
            "Experiment type must be 'plaintext' or 'key'."
        )

    if bit_index < 0 or bit_index > 127:
        raise ValueError(
            "Bit index must be between 0 and 127."
        )

    # --------------------------------------------------------
    # CREATE MODIFIED INPUT
    # --------------------------------------------------------

    modified_plaintext = plaintext_bytes
    modified_key = key_bytes

    if experiment_type == "plaintext":

        modified_plaintext = flip_bit(
            plaintext_bytes,
            bit_index
        )

    else:

        modified_key = flip_bit(
            key_bytes,
            bit_index
        )

    # --------------------------------------------------------
    # RUN BOTH AES EXECUTIONS
    # --------------------------------------------------------

    original_run = encrypt_block_with_steps(
        plaintext_bytes,
        key_bytes
    )

    modified_run = encrypt_block_with_steps(
        modified_plaintext,
        modified_key
    )

    original_steps = original_run["steps"]
    modified_steps = modified_run["steps"]

    if len(original_steps) != len(modified_steps):
        raise ValueError(
            "AES executions returned different step counts."
        )

    comparisons = []

    # --------------------------------------------------------
    # COMPARE ALL 41 RECORDED AES STATES
    # --------------------------------------------------------

    for index in range(
        len(original_steps)
    ):

        original_step = original_steps[index]
        modified_step = modified_steps[index]

        original_state_bytes = (
            state_matrix_to_bytes(
                original_step["state"]
            )
        )

        modified_state_bytes = (
            state_matrix_to_bytes(
                modified_step["state"]
            )
        )

        distance = hamming_distance_bytes(
            original_state_bytes,
            modified_state_bytes
        )

        percentage = (
            distance / 128.0
        ) * 100.0

        comparisons.append({
            "step": index + 1,
            "round": original_step["round"],
            "operation": original_step["operation"],
            "hamming_distance": distance,
            "avalanche_percentage": round(
                percentage,
                2
            ),
            "original_state":
                original_step["state"],
            "modified_state":
                modified_step["state"]
        })

    # --------------------------------------------------------
    # FINAL CIPHERTEXT DIFFERENCE
    # --------------------------------------------------------

    original_ciphertext = bytes.fromhex(
        original_run["ciphertext_hex"]
    )

    modified_ciphertext = bytes.fromhex(
        modified_run["ciphertext_hex"]
    )

    final_distance = hamming_distance_bytes(
        original_ciphertext,
        modified_ciphertext
    )

    final_percentage = (
        final_distance / 128.0
    ) * 100.0

    # --------------------------------------------------------
    # BIT LOCATION INFORMATION
    # --------------------------------------------------------

    byte_index = bit_index // 8
    bit_in_byte = bit_index % 8

    return {
        "experiment_type": experiment_type,
        "bit_index": bit_index,
        "byte_index": byte_index,
        "bit_in_byte_from_msb": bit_in_byte,

        "original_plaintext_hex":
            plaintext_bytes.hex().upper(),

        "modified_plaintext_hex":
            modified_plaintext.hex().upper(),

        "original_key_hex":
            key_bytes.hex().upper(),

        "modified_key_hex":
            modified_key.hex().upper(),

        "original_ciphertext_hex":
            original_run["ciphertext_hex"],

        "modified_ciphertext_hex":
            modified_run["ciphertext_hex"],

        "total_steps":
            len(comparisons),

        "final_hamming_distance":
            final_distance,

        "final_avalanche_percentage":
            round(
                final_percentage,
                2
            ),

        "comparisons":
            comparisons
    }

# ============================================================
# PHASE 10A — AES-128 LAB EXPERIMENT ENGINE
# ============================================================

import math


def calculate_statistics(values):
    """
    Calculate basic descriptive statistics for a numeric dataset.

    Population standard deviation is used because the selected
    trials are treated as the complete experimental dataset.
    """

    if not values:
        raise ValueError(
            "Cannot calculate statistics for an empty dataset."
        )

    count = len(values)

    mean = sum(values) / count

    minimum = min(values)
    maximum = max(values)

    variance = sum(
        (value - mean) ** 2
        for value in values
    ) / count

    standard_deviation = math.sqrt(
        variance
    )

    return {
        "count": count,
        "mean": round(mean, 4),
        "minimum": minimum,
        "maximum": maximum,
        "standard_deviation": round(
            standard_deviation,
            4
        )
    }


def multi_trial_avalanche_experiment(
    plaintext_bytes,
    key_bytes,
    experiment_type,
    start_bit,
    end_bit
):
    """
    Run repeated one-bit AES-128 avalanche experiments.

    experiment_type:
        plaintext
        key

    start_bit and end_bit are inclusive.
    """

    if len(plaintext_bytes) != 16:
        raise ValueError(
            "Plaintext must contain exactly 16 bytes."
        )

    if len(key_bytes) != 16:
        raise ValueError(
            "AES-128 key must contain exactly 16 bytes."
        )

    if experiment_type not in (
        "plaintext",
        "key"
    ):
        raise ValueError(
            "Experiment type must be 'plaintext' or 'key'."
        )

    if (
        start_bit < 0
        or start_bit > 127
        or end_bit < 0
        or end_bit > 127
    ):
        raise ValueError(
            "Bit range must be between 0 and 127."
        )

    if start_bit > end_bit:
        raise ValueError(
            "start_bit must be less than or equal to end_bit."
        )

    observations = []

    # --------------------------------------------------------
    # RUN EACH ONE-BIT EXPERIMENT
    # --------------------------------------------------------

    for bit_index in range(
        start_bit,
        end_bit + 1
    ):

        analysis = avalanche_analysis(
            plaintext_bytes,
            key_bytes,
            experiment_type,
            bit_index
        )

        observations.append({
            "trial": len(observations) + 1,
            "bit_index": bit_index,
            "byte_index":
                analysis["byte_index"],
            "bit_in_byte_from_msb":
                analysis["bit_in_byte_from_msb"],
            "final_hamming_distance":
                analysis["final_hamming_distance"],
            "final_avalanche_percentage":
                analysis["final_avalanche_percentage"],
            "modified_plaintext_hex":
                analysis["modified_plaintext_hex"],
            "modified_key_hex":
                analysis["modified_key_hex"],
            "modified_ciphertext_hex":
                analysis["modified_ciphertext_hex"]
        })

    # --------------------------------------------------------
    # EXTRACT NUMERIC RESULTS
    # --------------------------------------------------------

    hamming_values = [
        item["final_hamming_distance"]
        for item in observations
    ]

    avalanche_values = [
        item["final_avalanche_percentage"]
        for item in observations
    ]

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    hamming_statistics = (
        calculate_statistics(
            hamming_values
        )
    )

    avalanche_statistics = (
        calculate_statistics(
            avalanche_values
        )
    )

    # --------------------------------------------------------
    # DISTANCE FROM IDEAL 50%
    # --------------------------------------------------------

    mean_avalanche = (
        avalanche_statistics["mean"]
    )

    distance_from_50 = abs(
        50.0 - mean_avalanche
    )

    # --------------------------------------------------------
    # RESULT INTERPRETATION
    # --------------------------------------------------------

    if distance_from_50 <= 2.0:

        interpretation = (
            "The mean avalanche percentage is very close "
            "to the ideal 50% reference for this experiment."
        )

    elif distance_from_50 <= 5.0:

        interpretation = (
            "The mean avalanche percentage is reasonably "
            "close to the 50% reference for this experiment."
        )

    else:

        interpretation = (
            "The selected trial set shows a larger deviation "
            "from the 50% reference. More trials may provide "
            "a more representative measurement."
        )

    # --------------------------------------------------------
    # RETURN LAB DATA
    # --------------------------------------------------------

    return {
        "experiment_type":
            experiment_type,

        "plaintext_hex":
            plaintext_bytes.hex().upper(),

        "key_hex":
            key_bytes.hex().upper(),

        "start_bit":
            start_bit,

        "end_bit":
            end_bit,

        "total_trials":
            len(observations),

        "ideal_avalanche_percentage":
            50.0,

        "ideal_hamming_distance":
            64,

        "hamming_statistics":
            hamming_statistics,

        "avalanche_statistics":
            avalanche_statistics,

        "mean_distance_from_50_percent":
            round(
                distance_from_50,
                4
            ),

        "interpretation":
            interpretation,

        "observations":
            observations
    }

