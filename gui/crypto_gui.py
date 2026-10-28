import tkinter as tk
from tkinter import ttk, filedialog
from tkinter import messagebox, scrolledtext
import requests
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import csv
from tkinter import filedialog

API_URL = "http://localhost:8000"

# ============================================================
# AES S-BOX
# ============================================================

AES_SBOX = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
     0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],

    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
     0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],

    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
     0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],

    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
     0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],

    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
     0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],

    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
     0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],

    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
     0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],

    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
     0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],

    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
     0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],

    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
     0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],

    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
     0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],

    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
     0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],

    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
     0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],

    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
     0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],

    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
     0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],

    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
     0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]


# ============================================================
# AES GF(2^8) HELPERS — PHASE 7E
# ============================================================

def aes_xtime(value):

    value &= 0xFF

    if value & 0x80:

        return (
            ((value << 1) & 0xFF)
            ^ 0x1B
        )

    return (
        (value << 1) & 0xFF
    )


def aes_mul2(value):

    return aes_xtime(value)


def aes_mul3(value):

    return (
        aes_xtime(value)
        ^ value
    )


def aes_gf_multiply(
    coefficient,
    value
):

    if coefficient == 0x01:

        return value

    if coefficient == 0x02:

        return aes_mul2(value)

    if coefficient == 0x03:

        return aes_mul3(value)

    raise ValueError(
        "Phase 7E supports AES MixColumns "
        "coefficients 01, 02 and 03."
    )

# ------------------------------------------------
# API FUNCTIONS
# ------------------------------------------------

def generate_key():

    try:
        response = requests.get(
            f"{API_URL}/aes/generate-key",
            timeout=5
        )

        response.raise_for_status()

        data = response.json()

        key_entry.delete(0, tk.END)
        key_entry.insert(0, data["key"])

        status_label.config(
            text="AES-128 key generated successfully"
        )

    except Exception as e:
        messagebox.showerror(
            "API Error",
            str(e)
        )


def encrypt():

    plaintext = plaintext_box.get(
        "1.0",
        tk.END
    ).strip()

    key = key_entry.get().strip()

    if not plaintext:
        messagebox.showwarning(
            "Missing Plaintext",
            "Please enter plaintext."
        )
        return

    if not key:
        messagebox.showwarning(
            "Missing Key",
            "Please generate an AES key first."
        )
        return

    try:

        response = requests.post(
            f"{API_URL}/aes/encrypt",
            json={
                "plaintext": plaintext,
                "key": key
            },
            timeout=5
        )

        response.raise_for_status()

        data = response.json()

        ciphertext_box.delete(
            "1.0",
            tk.END
        )

        ciphertext_box.insert(
            tk.END,
            data["ciphertext"]
        )

        nonce_entry.delete(
            0,
            tk.END
        )

        nonce_entry.insert(
            0,
            data["nonce"]
        )

        decrypted_box.delete(
            "1.0",
            tk.END
        )

        status_label.config(
            text="Encryption successful"
        )

    except Exception as e:

        messagebox.showerror(
            "Encryption Error",
            str(e)
        )


def decrypt():

    ciphertext = ciphertext_box.get(
        "1.0",
        tk.END
    ).strip()

    key = key_entry.get().strip()

    nonce = nonce_entry.get().strip()

    if not ciphertext:
        messagebox.showwarning(
            "Missing Ciphertext",
            "Please encrypt a message first."
        )
        return

    if not key or not nonce:
        messagebox.showwarning(
            "Missing Data",
            "AES key or nonce is missing."
        )
        return

    try:

        response = requests.post(
            f"{API_URL}/aes/decrypt",
            json={
                "ciphertext": ciphertext,
                "nonce": nonce,
                "key": key
            },
            timeout=5
        )

        response.raise_for_status()

        data = response.json()

        decrypted_box.delete(
            "1.0",
            tk.END
        )

        decrypted_box.insert(
            tk.END,
            data["plaintext"]
        )

        status_label.config(
            text="Decryption successful"
        )

    except Exception as e:

        messagebox.showerror(
            "Decryption Error",
            str(e)
        )


def clear_all():

    plaintext_box.delete(
        "1.0",
        tk.END
    )

    key_entry.delete(
        0,
        tk.END
    )

    ciphertext_box.delete(
        "1.0",
        tk.END
    )

    nonce_entry.delete(
        0,
        tk.END
    )

    decrypted_box.delete(
        "1.0",
        tk.END
    )

    status_label.config(
        text="Ready"
    )


def open_aes_visualizer():

    visualizer = tk.Toplevel(root)

    visualizer.title(
        "Interactive AES-128 Teaching Visualizer"
    )

    visualizer.geometry("1050x780")

    # ------------------------------------------------
    # DATA STORAGE
    # ------------------------------------------------

    aes_steps = []
    current_step = [0]

    # ------------------------------------------------
    # TITLE
    # ------------------------------------------------

    tk.Label(
        visualizer,
        text="Interactive AES-128 Teaching Visualizer",
        font=("Arial", 18, "bold")
    ).pack(pady=5)

    tk.Label(
        visualizer,
        text=(
            "Explore the actual internal states "
            "of AES-128 encryption"
        ),
        font=("Arial", 12)
    ).pack()

    # ------------------------------------------------
    # INPUT FRAME
    # ------------------------------------------------

    input_frame = tk.LabelFrame(
        visualizer,
        text="AES Input",
        font=("Arial", 12, "bold"),
        padx=15,
        pady=10
    )

    input_frame.pack(
        padx=20,
        pady=5,
        fill="x"
    )

    tk.Label(
        input_frame,
        text="Plaintext — 16 bytes / 32 hexadecimal characters:"
    ).grid(
        row=0,
        column=0,
        sticky="w"
    )

    plaintext_hex_entry = tk.Entry(
        input_frame,
        font=("Courier", 12),
        width=40
    )

    plaintext_hex_entry.grid(
        row=1,
        column=0,
        padx=5,
        pady=5,
        sticky="w"
    )

    plaintext_hex_entry.insert(
        0,
        "00112233445566778899AABBCCDDEEFF"
    )

    tk.Label(
        input_frame,
        text="AES-128 Key — 16 bytes / 32 hexadecimal characters:"
    ).grid(
        row=2,
        column=0,
        sticky="w",
        pady=(10, 0)
    )

    key_hex_entry = tk.Entry(
        input_frame,
        font=("Courier", 12),
        width=40
    )

    key_hex_entry.grid(
        row=3,
        column=0,
        padx=5,
        pady=5,
        sticky="w"
    )

    key_hex_entry.insert(
        0,
        "000102030405060708090A0B0C0D0E0F"
    )

    # ------------------------------------------------
    # INFORMATION LABELS
    # ------------------------------------------------

    step_label = tk.Label(
        visualizer,
        text="Run AES to begin",
        font=("Arial", 16, "bold")
    )

    step_label.pack(pady=(10, 2))

    operation_label = tk.Label(
        visualizer,
        text="",
        font=("Arial", 14)
    )

    operation_label.pack()

    # ------------------------------------------------
    # STATE + ROUND KEY AREA
    # ------------------------------------------------

    matrices_frame = tk.Frame(visualizer)

    matrices_frame.pack(
        pady=5
    )

    # ---------------- CURRENT STATE ----------------

    state_frame = tk.LabelFrame(
        matrices_frame,
        text="Current AES State",
        font=("Arial", 12, "bold"),
        padx=15,
        pady=15
    )

    state_frame.pack(
        side="left",
        padx=20
    )

    state_labels = []

    for row in range(4):

        current_row = []

        for col in range(4):

            label = tk.Label(
                state_frame,
                text="--",
                width=5,
                height=1,
                relief="solid",
                font=("Courier", 15, "bold")
            )

            label.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            current_row.append(label)

        state_labels.append(current_row)

    # ---------------- ROUND KEY ----------------

    round_key_frame = tk.LabelFrame(
        matrices_frame,
        text="Round Key",
        font=("Arial", 12, "bold"),
        padx=15,
        pady=15
    )

    round_key_frame.pack(
        side="left",
        padx=20
    )

    round_key_labels = []

    for row in range(4):

        current_row = []

        for col in range(4):

            label = tk.Label(
                round_key_frame,
                text="--",
                width=5,
                height=2,
                relief="solid",
                font=("Courier", 15, "bold")
            )

            label.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            current_row.append(label)

        round_key_labels.append(current_row)

    # ------------------------------------------------
    # DESCRIPTION
    # ------------------------------------------------

    description_box = scrolledtext.ScrolledText(
        visualizer,
        height=4,
        width=90,
        wrap=tk.WORD
    )

    description_box.pack(
        padx=25,
        pady=5
    )

    description_box.insert(
        tk.END,
        "Enter a 16-byte plaintext block and "
        "AES-128 key, then click Run AES."
    )

    description_box.config(
        state="disabled"
    )

    # ------------------------------------------------
    # CIPHERTEXT
    # ------------------------------------------------

    ciphertext_label = tk.Label(
        visualizer,
        text="Ciphertext: —",
        font=("Courier", 12, "bold")
    )

    ciphertext_label.pack(
        pady=8
    )

    # ------------------------------------------------
    # UPDATE DISPLAY
    # ------------------------------------------------

    def display_step(index):

        if not aes_steps:
            return

        if index < 0 or index >= len(aes_steps):
            return

        current_step[0] = index

        step = aes_steps[index]

        state = step["state"]

        # Update state matrix

        for row in range(4):
            for col in range(4):

                state_labels[row][col].config(
                    text=state[row][col]
                )

        # Update round key

        round_key = step.get("round_key")

        for row in range(4):
            for col in range(4):

                if round_key:

                    round_key_labels[row][col].config(
                        text=round_key[row][col]
                    )

                else:

                    round_key_labels[row][col].config(
                        text="--"
                    )

        # Step information

        step_label.config(
            text=(
                f"Step {index + 1} / {len(aes_steps)}"
            )
        )

        operation_label.config(
            text=(
                f"Round {step['round']} — "
                f"{step['operation']}"
            )
        )

        # Description

        description_box.config(
            state="normal"
        )

        description_box.delete(
            "1.0",
            tk.END
        )

        description_box.insert(
            tk.END,
            step["description"]
        )

        if round_key:

            description_box.insert(
                tk.END,
                "\n\nA round key is shown because "
                "this step performs AddRoundKey."
            )

        description_box.config(
            state="disabled"
        )

        # Navigation buttons

        previous_button.config(
            state=(
                tk.NORMAL
                if index > 0
                else tk.DISABLED
            )
        )

        next_button.config(
            state=(
                tk.NORMAL
                if index < len(aes_steps) - 1
                else tk.DISABLED
            )
        )

    # ------------------------------------------------
    # RUN AES
    # ------------------------------------------------

    def run_visualization():

        plaintext_hex = (
            plaintext_hex_entry.get()
            .replace(" ", "")
            .strip()
        )

        key_hex = (
            key_hex_entry.get()
            .replace(" ", "")
            .strip()
        )

        if len(plaintext_hex) != 32:

            messagebox.showwarning(
                "Invalid Plaintext",
                "Enter exactly 32 hexadecimal "
                "characters (16 bytes)."
            )

            return

        if len(key_hex) != 32:

            messagebox.showwarning(
                "Invalid Key",
                "Enter exactly 32 hexadecimal "
                "characters for AES-128."
            )

            return

        try:

            int(plaintext_hex, 16)
            int(key_hex, 16)

        except ValueError:

            messagebox.showwarning(
                "Invalid Hexadecimal Input",
                "Use hexadecimal characters "
                "0-9 and A-F only."
            )

            return

        try:

            response = requests.post(
                f"{API_URL}/aes/visualize",
                json={
                    "plaintext_hex": plaintext_hex,
                    "key_hex": key_hex
                },
                timeout=10
            )

            response.raise_for_status()

            data = response.json()

            aes_steps.clear()

            aes_steps.extend(
                data["steps"]
            )

            ciphertext_label.config(
                text=(
                    "Ciphertext: "
                    + data["ciphertext_hex"]
                )
            )

            display_step(0)

            jump_scale.config(
                from_=1,
                to=len(aes_steps)
            )

            jump_scale.set(1)

        except requests.exceptions.ConnectionError:

            messagebox.showerror(
                "Docker API Error",
                "Cannot connect to the cryptography API.\n\n"
                "Check that the Docker container is running."
            )

        except Exception as e:

            messagebox.showerror(
                "Visualization Error",
                str(e)
            )

    # ------------------------------------------------
    # NAVIGATION
    # ------------------------------------------------

    def previous_step():

        new_index = current_step[0] - 1

        display_step(new_index)

        jump_scale.set(
            new_index + 1
        )

    def next_step():

        new_index = current_step[0] + 1

        display_step(new_index)

        jump_scale.set(
            new_index + 1
        )

    def jump_to_step(value):

        if not aes_steps:
            return

        index = int(float(value)) - 1

        display_step(index)

    # ------------------------------------------------
    # RUN BUTTON
    # ------------------------------------------------

    run_button = tk.Button(
        input_frame,
        text="RUN AES",
        command=run_visualization,
        font=("Arial", 12, "bold"),
        width=15
    )

    run_button.grid(
        row=1,
        column=1,
        rowspan=3,
        padx=25
    )

    # ------------------------------------------------
    # NAVIGATION BUTTONS
    # ------------------------------------------------

    navigation_frame = tk.Frame(
        visualizer
    )

    navigation_frame.pack(
        pady=10
    )

    previous_button = tk.Button(
        navigation_frame,
        text="◀ Previous Step",
        command=previous_step,
        width=16,
        state=tk.DISABLED
    )

    previous_button.pack(
        side="left",
        padx=10
    )

    next_button = tk.Button(
        navigation_frame,
        text="Next Step ▶",
        command=next_step,
        width=16,
        state=tk.DISABLED
    )

    next_button.pack(
        side="left",
        padx=10
    )

    # ------------------------------------------------
    # STEP SLIDER
    # ------------------------------------------------

    tk.Label(
        visualizer,
        text="Jump to Step:",
	font=("Arial", 11, "bold")
    ).pack(
	pady=(3, 0)
    )

    jump_scale = tk.Scale(
        visualizer,
        from_=1,
        to=41,
        orient="horizontal",
        length=650,
        command=jump_to_step,
	showvalue=True,
	tickinterval=5
    )

    jump_scale.pack(
        pady=(0, 5)
    )

# ============================================================
# PHASE 7A DASHBOARD FUNCTIONS
# ============================================================

# ============================================================
# PHASE 7B — BEFORE / AFTER TRANSFORMATION LAB
# ============================================================

def open_transformation_lab():

    lab = tk.Toplevel(root)

    lab.title(
        "AES-128 Transformation Laboratory"
    )

    lab.geometry(
        "1100x800"
    )

    lab.minsize(
        950,
        700
    )

    # --------------------------------------------------------
    # DATA
    # --------------------------------------------------------

    aes_steps = []

    transformation_indices = []

    selected_position = [0]

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    tk.Label(
        lab,
        text="AES-128 Transformation Laboratory",
        font=("Arial", 22, "bold")
    ).pack(
        pady=(15, 3)
    )

    tk.Label(
        lab,
        text=(
            "Observe how each AES transformation "
            "changes the 4 x 4 state matrix"
        ),
        font=("Arial", 12)
    ).pack(
        pady=(0, 10)
    )

    # --------------------------------------------------------
    # INPUT FRAME
    # --------------------------------------------------------

    input_frame = tk.LabelFrame(
        lab,
        text="AES-128 Input",
        font=("Arial", 11, "bold"),
        padx=12,
        pady=8
    )

    input_frame.pack(
        padx=20,
        pady=5,
        fill="x"
    )

    tk.Label(
        input_frame,
        text="Plaintext:"
    ).grid(
        row=0,
        column=0,
        sticky="w"
    )

    plaintext_entry = tk.Entry(
        input_frame,
        width=38,
        font=("Courier", 11)
    )

    plaintext_entry.grid(
        row=1,
        column=0,
        padx=(0, 20),
        pady=4
    )

    plaintext_entry.insert(
        0,
        "00112233445566778899AABBCCDDEEFF"
    )

    tk.Label(
        input_frame,
        text="AES-128 Key:"
    ).grid(
        row=0,
        column=1,
        sticky="w"
    )

    key_entry = tk.Entry(
        input_frame,
        width=38,
        font=("Courier", 11)
    )

    key_entry.grid(
        row=1,
        column=1,
        padx=(0, 20),
        pady=4
    )

    key_entry.insert(
        0,
        "000102030405060708090A0B0C0D0E0F"
    )

    # --------------------------------------------------------
    # TRANSFORMATION INFORMATION
    # --------------------------------------------------------

    transformation_label = tk.Label(
        lab,
        text="Run AES to load transformations",
        font=("Arial", 16, "bold")
    )

    transformation_label.pack(
        pady=(12, 2)
    )

    step_info_label = tk.Label(
        lab,
        text="",
        font=("Arial", 11)
    )

    step_info_label.pack()

    # --------------------------------------------------------
    # MATRIX AREA
    # --------------------------------------------------------

    matrix_area = tk.Frame(
        lab
    )

    matrix_area.pack(
        pady=12
    )

    # ---------------- BEFORE ----------------

    before_frame = tk.LabelFrame(
        matrix_area,
        text="BEFORE",
        font=("Arial", 13, "bold"),
        padx=15,
        pady=15
    )

    before_frame.pack(
        side="left",
        padx=20
    )

    before_labels = []

    for row in range(4):

        row_labels = []

        for col in range(4):

            label = tk.Label(
                before_frame,
                text="--",
                width=5,
                height=2,
                relief="solid",
                font=("Courier", 15, "bold")
            )

            label.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            row_labels.append(
                label
            )

        before_labels.append(
            row_labels
        )

    # ---------------- ARROW / OPERATION ----------------

    operation_frame = tk.Frame(
        matrix_area,
        width=180
    )

    operation_frame.pack(
        side="left",
        padx=10
    )

    operation_name_label = tk.Label(
        operation_frame,
        text="",
        font=("Arial", 14, "bold"),
        width=15
    )

    operation_name_label.pack(
        pady=(35, 5)
    )

    tk.Label(
        operation_frame,
        text="→",
        font=("Arial", 32, "bold")
    ).pack()

    # ---------------- AFTER ----------------

    after_frame = tk.LabelFrame(
        matrix_area,
        text="AFTER",
        font=("Arial", 13, "bold"),
        padx=15,
        pady=15
    )

    after_frame.pack(
        side="left",
        padx=20
    )

    after_labels = []

    for row in range(4):

        row_labels = []

        for col in range(4):

            label = tk.Label(
                after_frame,
                text="--",
                width=5,
                height=2,
                relief="solid",
                font=("Courier", 15, "bold")
            )

            label.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            row_labels.append(
                label
            )

        after_labels.append(
            row_labels
        )

    # --------------------------------------------------------
    # CHANGE ANALYSIS
    # --------------------------------------------------------

    analysis_frame = tk.LabelFrame(
        lab,
        text="Transformation Analysis",
        font=("Arial", 11, "bold"),
        padx=15,
        pady=8
    )

    analysis_frame.pack(
        padx=30,
        pady=5,
        fill="x"
    )

    changed_label = tk.Label(
        analysis_frame,
        text="Changed bytes: —",
        font=("Arial", 12, "bold")
    )

    changed_label.pack(
        anchor="w"
    )

    explanation_label = tk.Label(
        analysis_frame,
        text=(
            "Run AES to begin the transformation analysis."
        ),
        justify="left",
        wraplength=950,
        font=("Arial", 11)
    )

    explanation_label.pack(
        anchor="w",
        pady=(5, 0)
    )

    # --------------------------------------------------------
    # TRANSFORMATION EXPLANATIONS
    # --------------------------------------------------------

    explanations = {

        "AddRoundKey":
            (
                "AddRoundKey combines the AES state with "
                "the current round key using bitwise XOR. "
                "This is the transformation that directly "
                "introduces key material into the state."
            ),

        "SubBytes":
            (
                "SubBytes replaces every byte independently "
                "using the AES substitution box (S-box). "
                "It provides the non-linear component of AES."
            ),

        "ShiftRows":
            (
                "ShiftRows cyclically rotates the rows of the "
                "AES state. Row 0 is unchanged, while rows "
                "1, 2 and 3 are shifted left by 1, 2 and "
                "3 positions respectively."
            ),

        "MixColumns":
            (
                "MixColumns transforms each column using a "
                "fixed matrix over GF(2^8). This spreads the "
                "influence of each byte across its column "
                "and provides diffusion."
            )
    }

    # --------------------------------------------------------
    # MATRIX UPDATE
    # --------------------------------------------------------

    def update_matrix(
        labels,
        state
    ):

        for row in range(4):

            for col in range(4):

                labels[row][col].config(
                    text=state[row][col]
                )

    # --------------------------------------------------------
    # COUNT CHANGED BYTES
    # --------------------------------------------------------

    def count_changed_bytes(
        before,
        after
    ):

        count = 0

        for row in range(4):

            for col in range(4):

                if (
                    before[row][col]
                    != after[row][col]
                ):

                    count += 1

        return count

    # --------------------------------------------------------
    # DISPLAY TRANSFORMATION
    # --------------------------------------------------------

    def display_transformation(
        position
    ):

        if not transformation_indices:
            return

        if position < 0:
            return

        if position >= len(
            transformation_indices
        ):
            return

        selected_position[0] = position

        step_index = (
            transformation_indices[position]
        )

        current_step = (
            aes_steps[step_index]
        )

        previous_step = (
            aes_steps[step_index - 1]
        )

        before = previous_step["state"]

        after = current_step["state"]

        operation = (
            current_step["operation"]
        )

        round_number = (
            current_step["round"]
        )

        update_matrix(
            before_labels,
            before
        )

        update_matrix(
            after_labels,
            after
        )

        transformation_label.config(
            text=(
                f"Round {round_number} — "
                f"{operation}"
            )
        )

        operation_name_label.config(
            text=operation
        )

        step_info_label.config(
            text=(
                f"Transformation "
                f"{position + 1} / "
                f"{len(transformation_indices)}"
                f"    |    AES Step "
                f"{step_index + 1} / "
                f"{len(aes_steps)}"
            )
        )

        changed = count_changed_bytes(
            before,
            after
        )

        changed_label.config(
            text=(
                f"Changed bytes: "
                f"{changed} / 16"
            )
        )

        explanation_label.config(
            text=explanations.get(
                operation,
                current_step.get(
                    "description",
                    ""
                )
            )
        )

        previous_button.config(
            state=(
                tk.NORMAL
                if position > 0
                else tk.DISABLED
            )
        )

        next_button.config(
            state=(
                tk.NORMAL
                if position
                < len(
                    transformation_indices
                ) - 1
                else tk.DISABLED
            )
        )

        transformation_scale.set(
            position + 1
        )

    # --------------------------------------------------------
    # RUN AES
    # --------------------------------------------------------

    def run_aes():

        plaintext_hex = (
            plaintext_entry.get()
            .replace(" ", "")
            .strip()
        )

        key_hex = (
            key_entry.get()
            .replace(" ", "")
            .strip()
        )

        if len(plaintext_hex) != 32:

            messagebox.showwarning(
                "Invalid Plaintext",
                (
                    "Enter exactly 32 hexadecimal "
                    "characters."
                )
            )

            return

        if len(key_hex) != 32:

            messagebox.showwarning(
                "Invalid Key",
                (
                    "Enter exactly 32 hexadecimal "
                    "characters."
                )
            )

            return

        try:

            bytes.fromhex(
                plaintext_hex
            )

            bytes.fromhex(
                key_hex
            )

        except ValueError:

            messagebox.showwarning(
                "Invalid Hexadecimal",
                (
                    "Plaintext and key must contain "
                    "hexadecimal characters only."
                )
            )

            return

        try:

            response = requests.post(
                f"{API_URL}/aes/visualize",
                json={
                    "plaintext_hex":
                        plaintext_hex,
                    "key_hex":
                        key_hex
                },
                timeout=10
            )

            response.raise_for_status()

            data = response.json()

            aes_steps.clear()

            aes_steps.extend(
                data["steps"]
            )

            transformation_indices.clear()

            # Step 0 is the original Input.
            # Every subsequent recorded step represents
            # an AES transformation.

            for index in range(
                1,
                len(aes_steps)
            ):

                transformation_indices.append(
                    index
                )

            transformation_scale.config(
                from_=1,
                to=len(
                    transformation_indices
                )
            )

            display_transformation(
                0
            )

        except requests.exceptions.ConnectionError:

            messagebox.showerror(
                "Docker API Error",
                (
                    "Cannot connect to the AES "
                    "backend.\n\n"
                    "Check that the Docker "
                    "container is running."
                )
            )

        except Exception as e:

            messagebox.showerror(
                "AES Error",
                str(e)
            )

    # --------------------------------------------------------
    # RUN BUTTON
    # --------------------------------------------------------

    run_button = tk.Button(
        input_frame,
        text="RUN AES",
        command=run_aes,
        font=("Arial", 11, "bold"),
        width=14
    )

    run_button.grid(
        row=1,
        column=2,
        padx=10
    )

    # --------------------------------------------------------
    # NAVIGATION
    # --------------------------------------------------------

    def previous_transformation():

        new_position = (
            selected_position[0] - 1
        )

        display_transformation(
            new_position
        )

    def next_transformation():

        new_position = (
            selected_position[0] + 1
        )

        display_transformation(
            new_position
        )

    def jump_transformation(
        value
    ):

        if not transformation_indices:
            return

        position = (
            int(float(value)) - 1
        )

        if (
            position
            != selected_position[0]
        ):

            display_transformation(
                position
            )

    navigation_frame = tk.Frame(
        lab
    )

    navigation_frame.pack(
        pady=8
    )

    previous_button = tk.Button(
        navigation_frame,
        text="◀ Previous",
        command=previous_transformation,
        width=16,
        state=tk.DISABLED
    )

    previous_button.pack(
        side="left",
        padx=10
    )

    next_button = tk.Button(
        navigation_frame,
        text="Next ▶",
        command=next_transformation,
        width=16,
        state=tk.DISABLED
    )

    next_button.pack(
        side="left",
        padx=10
    )

    tk.Label(
        lab,
        text="Jump to Transformation:",
        font=("Arial", 10, "bold")
    ).pack()

    transformation_scale = tk.Scale(
        lab,
        from_=1,
        to=40,
        orient="horizontal",
        length=650,
        command=jump_transformation,
        showvalue=True,
        tickinterval=5
    )

    transformation_scale.pack(
        pady=(0, 10)
    )

# ============================================================
# PHASE 7C — SUBBYTES / S-BOX LABORATORY
# ============================================================

def open_subbytes_lab():

    lab = tk.Toplevel(root)

    lab.title(
        "AES-128 SubBytes and S-Box Laboratory"
    )

    lab.geometry(
        "1180x780"
    )

    lab.minsize(
        950,
        650
    )

    # ========================================================
    # SCROLLABLE WINDOW
    # ========================================================

    canvas = tk.Canvas(
        lab,
        highlightthickness=0
    )

    scrollbar = tk.Scrollbar(
        lab,
        orient="vertical",
        command=canvas.yview
    )

    content = tk.Frame(
        canvas
    )

    canvas_window = canvas.create_window(
        (0, 0),
        window=content,
        anchor="nw"
    )

    def update_scroll_region(event=None):

        canvas.configure(
            scrollregion=canvas.bbox("all")
        )

    def resize_content(event):

        canvas.itemconfigure(
            canvas_window,
            width=event.width
        )

    content.bind(
        "<Configure>",
        update_scroll_region
    )

    canvas.bind(
        "<Configure>",
        resize_content
    )

    canvas.configure(
        yscrollcommand=scrollbar.set
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    canvas.pack(
        side="left",
        fill="both",
        expand=True
    )

    # ========================================================
    # LAB DATA
    # ========================================================

    aes_steps = []

    subbytes_indices = []

    current_round_position = [0]
    selected_state_row = [0]
    selected_state_col = [0]

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    tk.Label(
        content,
        text="AES-128 SubBytes & S-Box Laboratory",
        font=("Arial", 21, "bold")
    ).pack(
        pady=(10, 2)
    )

    tk.Label(
        content,
        text=(
            "Select a state byte to trace its "
            "complete AES S-box substitution"
        ),
        font=("Arial", 11)
    ).pack(
        pady=(0, 6)
    )

    # --------------------------------------------------------
    # INPUT
    # --------------------------------------------------------

    input_frame = tk.LabelFrame(
        content,
        text="AES-128 Input",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=6
    )

    input_frame.pack(
        padx=20,
        pady=4,
        fill="x"
    )

    tk.Label(
        input_frame,
        text="Plaintext:"
    ).grid(
        row=0,
        column=0,
        sticky="w"
    )

    plaintext_entry = tk.Entry(
        input_frame,
        width=36,
        font=("Courier", 10)
    )

    plaintext_entry.grid(
        row=1,
        column=0,
        padx=(0, 15)
    )

    plaintext_entry.insert(
        0,
        "00112233445566778899AABBCCDDEEFF"
    )

    tk.Label(
        input_frame,
        text="Key:"
    ).grid(
        row=0,
        column=1,
        sticky="w"
    )

    key_entry = tk.Entry(
        input_frame,
        width=36,
        font=("Courier", 10)
    )

    key_entry.grid(
        row=1,
        column=1,
        padx=(0, 15)
    )

    key_entry.insert(
        0,
        "000102030405060708090A0B0C0D0E0F"
    )

    # --------------------------------------------------------
    # ROUND LABEL
    # --------------------------------------------------------

    round_label = tk.Label(
        content,
        text="Run AES to load SubBytes rounds",
        font=("Arial", 14, "bold")
    )

    round_label.pack(
        pady=(7, 2)
    )

    # --------------------------------------------------------
    # STATE AREA
    # --------------------------------------------------------

    state_area = tk.Frame(
        content
    )

    state_area.pack(
        pady=5
    )

    before_frame = tk.LabelFrame(
        state_area,
        text="BEFORE SUBBYTES",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=10
    )

    before_frame.pack(
        side="left",
        padx=12
    )

    before_buttons = []

    # --------------------------------------------------------
    # BYTE SELECTION
    # --------------------------------------------------------

    def select_byte(row, col):

        selected_state_row[0] = row
        selected_state_col[0] = col

        update_selected_byte()

    for row in range(4):

        button_row = []

        for col in range(4):

            button = tk.Button(
                before_frame,
                text="--",
                width=4,
                height=1,
                font=("Courier", 13, "bold"),
                command=lambda r=row, c=col:
                    select_byte(r, c)
            )

            button.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            button_row.append(
                button
            )

        before_buttons.append(
            button_row
        )

    tk.Label(
        state_area,
        text="  SubBytes  →  ",
        font=("Arial", 15, "bold")
    ).pack(
        side="left",
        padx=8
    )

    after_frame = tk.LabelFrame(
        state_area,
        text="AFTER SUBBYTES",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=10
    )

    after_frame.pack(
        side="left",
        padx=12
    )

    after_labels = []

    for row in range(4):

        label_row = []

        for col in range(4):

            label = tk.Label(
                after_frame,
                text="--",
                width=4,
                height=1,
                relief="solid",
                font=("Courier", 13, "bold")
            )

            label.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            label_row.append(
                label
            )

        after_labels.append(
            label_row
        )

    # --------------------------------------------------------
    # LOOKUP EXPLANATION
    # --------------------------------------------------------

    lookup_label = tk.Label(
        content,
        text="Select a byte after running AES.",
        font=("Courier", 12, "bold")
    )

    lookup_label.pack(
        pady=5
    )

    # --------------------------------------------------------
    # S-BOX
    # --------------------------------------------------------

    sbox_frame = tk.LabelFrame(
        content,
        text="AES Forward S-Box",
        font=("Arial", 11, "bold"),
        padx=5,
        pady=5
    )

    sbox_frame.pack(
        padx=15,
        pady=5
    )

    # Corner

    tk.Label(
        sbox_frame,
        text="",
        width=3
    ).grid(
        row=0,
        column=0
    )

    # Column headings

    for col in range(16):

        tk.Label(
            sbox_frame,
            text=f"{col:X}",
            width=3,
            font=("Courier", 9, "bold")
        ).grid(
            row=0,
            column=col + 1
        )

    # Row headings + S-box cells

    sbox_labels = []

    for row in range(16):

        tk.Label(
            sbox_frame,
            text=f"{row:X}",
            width=3,
            font=("Courier", 9, "bold")
        ).grid(
            row=row + 1,
            column=0
        )

        label_row = []

        for col in range(16):

            label = tk.Label(
                sbox_frame,
                text=f"{AES_SBOX[row][col]:02X}",
                width=3,
                relief="groove",
                font=("Courier", 9)
            )

            label.grid(
                row=row + 1,
                column=col + 1,
                padx=1,
                pady=1
            )

            label_row.append(
                label
            )

        sbox_labels.append(
            label_row
        )

    # Save normal appearance so we can restore it.

    normal_sbox_bg = (
        sbox_labels[0][0].cget("background")
    )

    # --------------------------------------------------------
    # TEACHING TEXT
    # --------------------------------------------------------

    teaching_label = tk.Label(
        content,
        text=(
            "AES uses the high hexadecimal nibble as the "
            "S-box row and the low hexadecimal nibble "
            "as the S-box column."
        ),
        justify="left",
        wraplength=1050,
        font=("Arial", 10)
    )

    teaching_label.pack(
        padx=20,
        pady=4
    )

    # --------------------------------------------------------
    # UPDATE SELECTED BYTE
    # --------------------------------------------------------

    def update_selected_byte():

        if not subbytes_indices:
            return

        step_index = (
            subbytes_indices[
                current_round_position[0]
            ]
        )

        before = (
            aes_steps[step_index - 1]["state"]
        )

        after = (
            aes_steps[step_index]["state"]
        )

        row = selected_state_row[0]
        col = selected_state_col[0]

        input_hex = before[row][col]
        output_hex = after[row][col]

        input_value = int(
            input_hex,
            16
        )

        sbox_row = (
            input_value >> 4
        )

        sbox_col = (
            input_value & 0x0F
        )

        calculated_output = (
            AES_SBOX[sbox_row][sbox_col]
        )

        # Reset state buttons

        for r in range(4):

            for c in range(4):

                before_buttons[r][c].config(
                    relief="raised"
                )

                after_labels[r][c].config(
                    relief="solid"
                )

        before_buttons[row][col].config(
            relief="sunken"
        )

        after_labels[row][col].config(
            relief="sunken"
        )

        # Reset S-box

        for r in range(16):

            for c in range(16):

                sbox_labels[r][c].config(
                    background=normal_sbox_bg,
                    relief="groove"
                )

        # Highlight selected lookup

        sbox_labels[sbox_row][sbox_col].config(
            background="yellow",
            relief="solid"
        )

        lookup_label.config(
            text=(
                f"State[{row}][{col}] = "
                f"{input_hex}    →    "
                f"High nibble {sbox_row:X} = Row "
                f"{sbox_row:X}, "
                f"Low nibble {sbox_col:X} = Column "
                f"{sbox_col:X}    →    "
                f"S-Box[{sbox_row:X}]"
                f"[{sbox_col:X}] = "
                f"{calculated_output:02X}    →    "
                f"Output = {output_hex}"
            )
        )

    # --------------------------------------------------------
    # DISPLAY SUBBYTES ROUND
    # --------------------------------------------------------

    def display_subbytes_round(position):

        if not subbytes_indices:
            return

        if (
            position < 0
            or position >= len(
                subbytes_indices
            )
        ):
            return

        current_round_position[0] = position

        step_index = (
            subbytes_indices[position]
        )

        before = (
            aes_steps[step_index - 1]["state"]
        )

        after = (
            aes_steps[step_index]["state"]
        )

        round_number = (
            aes_steps[step_index]["round"]
        )

        for row in range(4):

            for col in range(4):

                before_buttons[row][col].config(
                    text=before[row][col]
                )

                after_labels[row][col].config(
                    text=after[row][col]
                )

        round_label.config(
            text=(
                f"Round {round_number} — SubBytes "
                f"({position + 1} / "
                f"{len(subbytes_indices)})"
            )
        )

        round_scale.set(
            position + 1
        )

        previous_round_button.config(
            state=(
                tk.NORMAL
                if position > 0
                else tk.DISABLED
            )
        )

        next_round_button.config(
            state=(
                tk.NORMAL
                if position <
                len(subbytes_indices) - 1
                else tk.DISABLED
            )
        )

        update_selected_byte()

    # --------------------------------------------------------
    # RUN AES
    # --------------------------------------------------------

    def run_aes():

        plaintext_hex = (
            plaintext_entry.get()
            .replace(" ", "")
            .strip()
        )

        key_hex = (
            key_entry.get()
            .replace(" ", "")
            .strip()
        )

        if (
            len(plaintext_hex) != 32
            or len(key_hex) != 32
        ):

            messagebox.showwarning(
                "Invalid AES-128 Input",
                (
                    "Plaintext and key must each "
                    "contain exactly 32 hexadecimal "
                    "characters."
                )
            )

            return

        try:

            bytes.fromhex(plaintext_hex)
            bytes.fromhex(key_hex)

        except ValueError:

            messagebox.showwarning(
                "Invalid Hexadecimal",
                (
                    "Plaintext and key must contain "
                    "hexadecimal characters only."
                )
            )

            return

        try:

            response = requests.post(
                f"{API_URL}/aes/visualize",
                json={
                    "plaintext_hex":
                        plaintext_hex,
                    "key_hex":
                        key_hex
                },
                timeout=10
            )

            response.raise_for_status()

            data = response.json()

            aes_steps.clear()

            aes_steps.extend(
                data["steps"]
            )

            subbytes_indices.clear()

            # Find the actual SubBytes steps returned
            # by the teaching backend.

            for index, step in enumerate(
                aes_steps
            ):

                if (
                    step["operation"]
                    == "SubBytes"
                ):

                    subbytes_indices.append(
                        index
                    )

            if len(subbytes_indices) != 10:

                messagebox.showwarning(
                    "Unexpected AES Data",
                    (
                        "Expected 10 SubBytes "
                        "transformations but received "
                        f"{len(subbytes_indices)}."
                    )
                )

                return

            round_scale.config(
                from_=1,
                to=len(subbytes_indices)
            )

            selected_state_row[0] = 0
            selected_state_col[0] = 0

            display_subbytes_round(
                0
            )

        except requests.exceptions.ConnectionError:

            messagebox.showerror(
                "Docker API Error",
                (
                    "Cannot connect to the AES "
                    "backend.\n\n"
                    "Check that crypto-api-container "
                    "is running."
                )
            )

        except Exception as e:

            messagebox.showerror(
                "AES Error",
                str(e)
            )

    # --------------------------------------------------------
    # RUN BUTTON
    # --------------------------------------------------------

    run_button = tk.Button(
        input_frame,
        text="RUN AES",
        command=run_aes,
        width=12,
        font=("Arial", 10, "bold")
    )

    run_button.grid(
        row=1,
        column=2,
        padx=10
    )

    # --------------------------------------------------------
    # ROUND NAVIGATION
    # --------------------------------------------------------

    def previous_round():

        display_subbytes_round(
            current_round_position[0] - 1
        )

    def next_round():

        display_subbytes_round(
            current_round_position[0] + 1
        )

    def jump_round(value):

        if not subbytes_indices:
            return

        position = (
            int(float(value)) - 1
        )

        if (
            position
            != current_round_position[0]
        ):

            display_subbytes_round(
                position
            )

    navigation_frame = tk.Frame(
        content
    )

    navigation_frame.pack(
        pady=3
    )

    previous_round_button = tk.Button(
        navigation_frame,
        text="◀ Previous Round",
        command=previous_round,
        width=16,
        state=tk.DISABLED
    )

    previous_round_button.pack(
        side="left",
        padx=8
    )

    next_round_button = tk.Button(
        navigation_frame,
        text="Next Round ▶",
        command=next_round,
        width=16,
        state=tk.DISABLED
    )

    next_round_button.pack(
        side="left",
        padx=8
    )

    round_scale = tk.Scale(
        content,
        from_=1,
        to=10,
        orient="horizontal",
        length=500,
        command=jump_round,
        showvalue=True,
        tickinterval=1
    )

    round_scale.pack(
        pady=(0, 8)
    )

        # --------------------------------------------------------
    # MOUSE / TRACKPAD SCROLLING
    # --------------------------------------------------------

    def mousewheel_scroll(event):

        if event.delta > 0:

            canvas.yview_scroll(
                -1,
                "units"
            )

        elif event.delta < 0:

            canvas.yview_scroll(
                1,
                "units"
            )

    def enable_mousewheel(event):

        lab.bind_all(
            "<MouseWheel>",
            mousewheel_scroll
        )

    def disable_mousewheel(event):

        lab.unbind_all(
            "<MouseWheel>"
        )

    canvas.bind(
        "<Enter>",
        enable_mousewheel
    )

    canvas.bind(
        "<Leave>",
        disable_mousewheel
    )

# ============================================================
# PHASE 7D — SHIFTROWS LABORATORY
# ============================================================

def open_shiftrows_lab():

    lab = tk.Toplevel(root)

    lab.title(
        "AES-128 ShiftRows Laboratory"
    )

    lab.geometry(
        "1050x760"
    )

    lab.minsize(
        900,
        650
    )

    aes_steps = []
    shiftrows_indices = []

    current_round_position = [0]

    selected_row = [0]
    selected_col = [0]

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    tk.Label(
        lab,
        text="AES-128 ShiftRows Laboratory",
        font=("Arial", 22, "bold")
    ).pack(
        pady=(12, 2)
    )

    tk.Label(
        lab,
        text=(
            "Visualize the cyclic movement of bytes "
            "within each AES state row"
        ),
        font=("Arial", 11)
    ).pack(
        pady=(0, 8)
    )

    # --------------------------------------------------------
    # INPUT
    # --------------------------------------------------------

    input_frame = tk.LabelFrame(
        lab,
        text="AES-128 Input",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=7
    )

    input_frame.pack(
        padx=20,
        pady=4,
        fill="x"
    )

    tk.Label(
        input_frame,
        text="Plaintext:"
    ).grid(
        row=0,
        column=0,
        sticky="w"
    )

    plaintext_entry = tk.Entry(
        input_frame,
        width=36,
        font=("Courier", 10)
    )

    plaintext_entry.grid(
        row=1,
        column=0,
        padx=(0, 15)
    )

    plaintext_entry.insert(
        0,
        "00112233445566778899AABBCCDDEEFF"
    )

    tk.Label(
        input_frame,
        text="Key:"
    ).grid(
        row=0,
        column=1,
        sticky="w"
    )

    key_entry = tk.Entry(
        input_frame,
        width=36,
        font=("Courier", 10)
    )

    key_entry.grid(
        row=1,
        column=1,
        padx=(0, 15)
    )

    key_entry.insert(
        0,
        "000102030405060708090A0B0C0D0E0F"
    )

    # --------------------------------------------------------
    # ROUND INFORMATION
    # --------------------------------------------------------

    round_label = tk.Label(
        lab,
        text="Run AES to load ShiftRows rounds",
        font=("Arial", 15, "bold")
    )

    round_label.pack(
        pady=(10, 3)
    )

    # --------------------------------------------------------
    # MATRIX AREA
    # --------------------------------------------------------

    matrix_area = tk.Frame(
        lab
    )

    matrix_area.pack(
        pady=10
    )

    # --------------------------------------------------------
    # BEFORE MATRIX
    # --------------------------------------------------------

    before_frame = tk.LabelFrame(
        matrix_area,
        text="BEFORE SHIFTROWS",
        font=("Arial", 12, "bold"),
        padx=12,
        pady=12
    )

    before_frame.pack(
        side="left",
        padx=20
    )

    before_buttons = []

    # --------------------------------------------------------
    # BYTE SELECTION
    # --------------------------------------------------------

    def select_byte(row, col):

        selected_row[0] = row
        selected_col[0] = col

        update_selected_byte()

    for row in range(4):

        button_row = []

        for col in range(4):

            button = tk.Button(
                before_frame,
                text="--",
                width=5,
                height=2,
                font=("Courier", 14, "bold"),
                command=lambda r=row, c=col:
                    select_byte(r, c)
            )

            button.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            button_row.append(
                button
            )

        before_buttons.append(
            button_row
        )

    # --------------------------------------------------------
    # SHIFT DESCRIPTION
    # --------------------------------------------------------

    shift_frame = tk.Frame(
        matrix_area
    )

    shift_frame.pack(
        side="left",
        padx=15
    )

    tk.Label(
        shift_frame,
        text="ShiftRows",
        font=("Arial", 14, "bold")
    ).pack(
        pady=(25, 5)
    )

    tk.Label(
        shift_frame,
        text=(
            "Row 0: ← 0\n"
            "Row 1: ← 1\n"
            "Row 2: ← 2\n"
            "Row 3: ← 3"
        ),
        font=("Courier", 12),
        justify="left"
    ).pack()

    tk.Label(
        shift_frame,
        text="→",
        font=("Arial", 30, "bold")
    ).pack(
        pady=5
    )

    # --------------------------------------------------------
    # AFTER MATRIX
    # --------------------------------------------------------

    after_frame = tk.LabelFrame(
        matrix_area,
        text="AFTER SHIFTROWS",
        font=("Arial", 12, "bold"),
        padx=12,
        pady=12
    )

    after_frame.pack(
        side="left",
        padx=20
    )

    after_labels = []

    for row in range(4):

        label_row = []

        for col in range(4):

            label = tk.Label(
                after_frame,
                text="--",
                width=5,
                height=2,
                relief="solid",
                font=("Courier", 14, "bold")
            )

            label.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            label_row.append(
                label
            )

        after_labels.append(
            label_row
        )

    # --------------------------------------------------------
    # ROW TRANSFORMATION TABLE
    # --------------------------------------------------------

    row_analysis_frame = tk.LabelFrame(
        lab,
        text="Row-by-Row Transformation",
        font=("Arial", 11, "bold"),
        padx=12,
        pady=8
    )

    row_analysis_frame.pack(
        padx=30,
        pady=5,
        fill="x"
    )

    row_analysis_labels = []

    for row in range(4):

        label = tk.Label(
            row_analysis_frame,
            text=f"Row {row}: —",
            font=("Courier", 11),
            anchor="w"
        )

        label.pack(
            anchor="w",
            pady=2
        )

        row_analysis_labels.append(
            label
        )

    # --------------------------------------------------------
    # SELECTED BYTE ANALYSIS
    # --------------------------------------------------------

    selected_frame = tk.LabelFrame(
        lab,
        text="Selected Byte Movement",
        font=("Arial", 11, "bold"),
        padx=12,
        pady=8
    )

    selected_frame.pack(
        padx=30,
        pady=5,
        fill="x"
    )

    selected_byte_label = tk.Label(
        selected_frame,
        text="Run AES and select a byte.",
        font=("Courier", 11, "bold"),
        justify="left"
    )

    selected_byte_label.pack(
        anchor="w"
    )

    # --------------------------------------------------------
    # UPDATE SELECTED BYTE
    # --------------------------------------------------------

    def update_selected_byte():

        if not shiftrows_indices:
            return

        step_index = (
            shiftrows_indices[
                current_round_position[0]
            ]
        )

        before = (
            aes_steps[step_index - 1]["state"]
        )

        after = (
            aes_steps[step_index]["state"]
        )

        row = selected_row[0]
        col = selected_col[0]

        byte_value = before[row][col]

        # ShiftRows performs a cyclic left shift
        # by the row number.
        #
        # A byte originally in column c therefore
        # appears at:
        #
        # destination = (c - row) mod 4

        destination_col = (
            col - row
        ) % 4

        destination_value = (
            after[row][destination_col]
        )

        # Reset visual selection

        for r in range(4):

            for c in range(4):

                before_buttons[r][c].config(
                    relief="raised"
                )

                after_labels[r][c].config(
                    relief="solid"
                )

        before_buttons[row][col].config(
            relief="sunken"
        )

        after_labels[row][destination_col].config(
            relief="sunken"
        )

        if row == 0:

            movement_text = (
                "Row 0 is not shifted."
            )

        else:

            movement_text = (
                f"Row {row} is cyclically shifted "
                f"{row} position"
                f"{'s' if row != 1 else ''} left."
            )

        selected_byte_label.config(
            text=(
                f"Selected byte: {byte_value}\n"
                f"Original position: "
                f"State[{row}][{col}]\n"
                f"Shift amount: {row} left\n"
                f"Destination position: "
                f"State[{row}]"
                f"[{destination_col}]\n"
                f"Destination value: "
                f"{destination_value}\n"
                f"{movement_text}"
            )
        )

    # --------------------------------------------------------
    # DISPLAY SHIFTROWS ROUND
    # --------------------------------------------------------

    def display_shiftrows_round(position):

        if not shiftrows_indices:
            return

        if (
            position < 0
            or position >= len(
                shiftrows_indices
            )
        ):
            return

        current_round_position[0] = position

        step_index = (
            shiftrows_indices[position]
        )

        before = (
            aes_steps[step_index - 1]["state"]
        )

        after = (
            aes_steps[step_index]["state"]
        )

        round_number = (
            aes_steps[step_index]["round"]
        )

        # Update matrices

        for row in range(4):

            for col in range(4):

                before_buttons[row][col].config(
                    text=before[row][col]
                )

                after_labels[row][col].config(
                    text=after[row][col]
                )

        # Update row-by-row explanation

        for row in range(4):

            before_row = " ".join(
                before[row]
            )

            after_row = " ".join(
                after[row]
            )

            row_analysis_labels[row].config(
                text=(
                    f"Row {row}:  "
                    f"{before_row}   "
                    f"→ left {row} →   "
                    f"{after_row}"
                )
            )

        round_label.config(
            text=(
                f"Round {round_number} — "
                f"ShiftRows "
                f"({position + 1} / "
                f"{len(shiftrows_indices)})"
            )
        )

        round_scale.set(
            position + 1
        )

        previous_round_button.config(
            state=(
                tk.NORMAL
                if position > 0
                else tk.DISABLED
            )
        )

        next_round_button.config(
            state=(
                tk.NORMAL
                if position <
                len(shiftrows_indices) - 1
                else tk.DISABLED
            )
        )

        update_selected_byte()

    # --------------------------------------------------------
    # RUN AES
    # --------------------------------------------------------

    def run_aes():

        plaintext_hex = (
            plaintext_entry.get()
            .replace(" ", "")
            .strip()
        )

        key_hex = (
            key_entry.get()
            .replace(" ", "")
            .strip()
        )

        if (
            len(plaintext_hex) != 32
            or len(key_hex) != 32
        ):

            messagebox.showwarning(
                "Invalid AES-128 Input",
                (
                    "Plaintext and key must each "
                    "contain exactly 32 hexadecimal "
                    "characters."
                )
            )

            return

        try:

            bytes.fromhex(
                plaintext_hex
            )

            bytes.fromhex(
                key_hex
            )

        except ValueError:

            messagebox.showwarning(
                "Invalid Hexadecimal",
                (
                    "Plaintext and key must contain "
                    "hexadecimal characters only."
                )
            )

            return

        try:

            response = requests.post(
                f"{API_URL}/aes/visualize",
                json={
                    "plaintext_hex":
                        plaintext_hex,
                    "key_hex":
                        key_hex
                },
                timeout=10
            )

            response.raise_for_status()

            data = response.json()

            aes_steps.clear()

            aes_steps.extend(
                data["steps"]
            )

            shiftrows_indices.clear()

            for index, step in enumerate(
                aes_steps
            ):

                if (
                    step["operation"]
                    == "ShiftRows"
                ):

                    shiftrows_indices.append(
                        index
                    )

            if len(shiftrows_indices) != 10:

                messagebox.showwarning(
                    "Unexpected AES Data",
                    (
                        "Expected 10 ShiftRows "
                        "transformations but received "
                        f"{len(shiftrows_indices)}."
                    )
                )

                return

            round_scale.config(
                from_=1,
                to=len(
                    shiftrows_indices
                )
            )

            selected_row[0] = 0
            selected_col[0] = 0

            display_shiftrows_round(
                0
            )

        except requests.exceptions.ConnectionError:

            messagebox.showerror(
                "Docker API Error",
                (
                    "Cannot connect to the AES "
                    "backend.\n\n"
                    "Check that crypto-api-container "
                    "is running."
                )
            )

        except Exception as e:

            messagebox.showerror(
                "AES Error",
                str(e)
            )

    # --------------------------------------------------------
    # RUN BUTTON
    # --------------------------------------------------------

    run_button = tk.Button(
        input_frame,
        text="RUN AES",
        command=run_aes,
        width=12,
        font=("Arial", 10, "bold")
    )

    run_button.grid(
        row=1,
        column=2,
        padx=10
    )

    # --------------------------------------------------------
    # ROUND NAVIGATION
    # --------------------------------------------------------

    def previous_round():

        display_shiftrows_round(
            current_round_position[0] - 1
        )

    def next_round():

        display_shiftrows_round(
            current_round_position[0] + 1
        )

    def jump_round(value):

        if not shiftrows_indices:
            return

        position = (
            int(float(value)) - 1
        )

        if (
            position
            != current_round_position[0]
        ):

            display_shiftrows_round(
                position
            )

    navigation_frame = tk.Frame(
        lab
    )

    navigation_frame.pack(
        pady=5
    )

    previous_round_button = tk.Button(
        navigation_frame,
        text="◀ Previous Round",
        command=previous_round,
        width=16,
        state=tk.DISABLED
    )

    previous_round_button.pack(
        side="left",
        padx=8
    )

    next_round_button = tk.Button(
        navigation_frame,
        text="Next Round ▶",
        command=next_round,
        width=16,
        state=tk.DISABLED
    )

    next_round_button.pack(
        side="left",
        padx=8
    )

    round_scale = tk.Scale(
        lab,
        from_=1,
        to=10,
        orient="horizontal",
        length=500,
        command=jump_round,
        showvalue=True,
        tickinterval=1
    )

    round_scale.pack(
        pady=(0, 8)
    )

# ============================================================
# PHASE 7E — MIXCOLUMNS / GF(2^8) LABORATORY
# ============================================================

def open_mixcolumns_lab():

    lab = tk.Toplevel(root)

    lab.title(
        "AES-128 MixColumns & GF(2^8) Laboratory"
    )

    lab.geometry(
        "1180x820"
    )

    lab.minsize(
        1000,
        700
    )

    aes_steps = []
    mixcolumns_indices = []

    current_round_position = [0]
    selected_column = [0]
    selected_output_row = [0]

    mix_matrix = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    tk.Label(
        lab,
        text="AES-128 MixColumns & GF(2⁸) Laboratory",
        font=("Arial", 21, "bold")
    ).pack(
        pady=(10, 2)
    )

    tk.Label(
        lab,
        text=(
            "Explore AES column mixing using finite-field "
            "multiplication and XOR"
        ),
        font=("Arial", 11)
    ).pack(
        pady=(0, 6)
    )

    # --------------------------------------------------------
    # INPUT
    # --------------------------------------------------------

    input_frame = tk.LabelFrame(
        lab,
        text="AES-128 Input",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=6
    )

    input_frame.pack(
        padx=20,
        pady=4,
        fill="x"
    )

    tk.Label(
        input_frame,
        text="Plaintext:"
    ).grid(
        row=0,
        column=0,
        sticky="w"
    )

    plaintext_entry = tk.Entry(
        input_frame,
        width=36,
        font=("Courier", 10)
    )

    plaintext_entry.grid(
        row=1,
        column=0,
        padx=(0, 15)
    )

    plaintext_entry.insert(
        0,
        "00112233445566778899AABBCCDDEEFF"
    )

    tk.Label(
        input_frame,
        text="Key:"
    ).grid(
        row=0,
        column=1,
        sticky="w"
    )

    key_entry = tk.Entry(
        input_frame,
        width=36,
        font=("Courier", 10)
    )

    key_entry.grid(
        row=1,
        column=1,
        padx=(0, 15)
    )

    key_entry.insert(
        0,
        "000102030405060708090A0B0C0D0E0F"
    )

    # --------------------------------------------------------
    # ROUND INFORMATION
    # --------------------------------------------------------

    round_label = tk.Label(
        lab,
        text="Run AES to load MixColumns rounds",
        font=("Arial", 15, "bold")
    )

    round_label.pack(
        pady=(8, 3)
    )

    # --------------------------------------------------------
    # MAIN VISUALIZATION
    # --------------------------------------------------------

    visual_frame = tk.Frame(
        lab
    )

    visual_frame.pack(
        pady=6
    )

    # BEFORE STATE

    before_frame = tk.LabelFrame(
        visual_frame,
        text="BEFORE MIXCOLUMNS",
        font=("Arial", 11, "bold"),
        padx=8,
        pady=8
    )

    before_frame.pack(
        side="left",
        padx=10
    )

    before_buttons = []

    def select_column(col):

        selected_column[0] = col

        update_column_analysis()

    for row in range(4):

        button_row = []

        for col in range(4):

            button = tk.Button(
                before_frame,
                text="--",
                width=4,
                height=1,
                font=("Courier", 13, "bold"),
                command=lambda c=col:
                    select_column(c)
            )

            button.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            button_row.append(
                button
            )

        before_buttons.append(
            button_row
        )

    # MULTIPLICATION SYMBOL

    tk.Label(
        visual_frame,
        text="  ×  ",
        font=("Arial", 25, "bold")
    ).pack(
        side="left"
    )

    # FIXED AES MATRIX

    coefficient_frame = tk.LabelFrame(
        visual_frame,
        text="AES MATRIX",
        font=("Arial", 11, "bold"),
        padx=8,
        pady=8
    )

    coefficient_frame.pack(
        side="left",
        padx=10
    )

    coefficient_labels = []

    for row in range(4):

        label_row = []

        for col in range(4):

            label = tk.Label(
                coefficient_frame,
                text=f"{mix_matrix[row][col]:02X}",
                width=4,
                height=1,
                relief="solid",
                font=("Courier", 13, "bold")
            )

            label.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            label_row.append(
                label
            )

        coefficient_labels.append(
            label_row
        )

    tk.Label(
        visual_frame,
        text="  →  ",
        font=("Arial", 25, "bold")
    ).pack(
        side="left"
    )

    # AFTER STATE

    after_frame = tk.LabelFrame(
        visual_frame,
        text="AFTER MIXCOLUMNS",
        font=("Arial", 11, "bold"),
        padx=8,
        pady=8
    )

    after_frame.pack(
        side="left",
        padx=10
    )

    after_labels = []

    for row in range(4):

        label_row = []

        for col in range(4):

            label = tk.Label(
                after_frame,
                text="--",
                width=4,
                height=1,
                relief="solid",
                font=("Courier", 13, "bold")
            )

            label.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            label_row.append(
                label
            )

        after_labels.append(
            label_row
        )

    # --------------------------------------------------------
    # SELECTED COLUMN
    # --------------------------------------------------------

    column_frame = tk.LabelFrame(
        lab,
        text="Selected Column",
        font=("Arial", 11, "bold"),
        padx=12,
        pady=7
    )

    column_frame.pack(
        padx=25,
        pady=4,
        fill="x"
    )

    column_label = tk.Label(
        column_frame,
        text="Run AES and select a state column.",
        font=("Courier", 11, "bold")
    )

    column_label.pack(
        anchor="w"
    )

    # --------------------------------------------------------
    # OUTPUT BYTE SELECTION
    # --------------------------------------------------------

    output_frame = tk.Frame(
        column_frame
    )

    output_frame.pack(
        anchor="w",
        pady=(6, 2)
    )

    tk.Label(
        output_frame,
        text="Explain output byte:",
        font=("Arial", 10, "bold")
    ).pack(
        side="left",
        padx=(0, 8)
    )

    output_buttons = []

    def select_output_row(row):

        selected_output_row[0] = row

        update_equation()

    for row in range(4):

        button = tk.Button(
            output_frame,
            text=f"b{row}",
            width=5,
            command=lambda r=row:
                select_output_row(r)
        )

        button.pack(
            side="left",
            padx=3
        )

        output_buttons.append(
            button
        )

    # --------------------------------------------------------
    # EQUATION
    # --------------------------------------------------------

    equation_frame = tk.LabelFrame(
        lab,
        text="GF(2⁸) Calculation",
        font=("Arial", 11, "bold"),
        padx=12,
        pady=8
    )

    equation_frame.pack(
        padx=25,
        pady=4,
        fill="both",
        expand=True
    )

    equation_text = scrolledtext.ScrolledText(
        equation_frame,
        height=10,
        width=110,
        wrap=tk.WORD,
        font=("Courier", 10)
    )

    equation_text.pack(
        fill="both",
        expand=True
    )

    equation_text.insert(
        tk.END,
        "Run AES to begin MixColumns analysis."
    )

    equation_text.config(
        state="disabled"
    )

    # --------------------------------------------------------
    # GF MULTIPLICATION EXPLANATION
    # --------------------------------------------------------

    def multiplication_explanation(
        coefficient,
        value
    ):

        if coefficient == 0x01:

            result = value

            return (
                f"01 × {value:02X} = "
                f"{result:02X} "
                f"(multiplication by 01 leaves "
                f"the byte unchanged)"
            )

        if coefficient == 0x02:

            shifted = (
                (value << 1) & 0xFF
            )

            if value & 0x80:

                result = (
                    shifted ^ 0x1B
                )

                return (
                    f"02 × {value:02X}: "
                    f"MSB=1, so xtime requires "
                    f"reduction. "
                    f"({value:02X} << 1) "
                    f"mod 100 = {shifted:02X}; "
                    f"{shifted:02X} XOR 1B = "
                    f"{result:02X}"
                )

            result = shifted

            return (
                f"02 × {value:02X}: "
                f"MSB=0, so left shift only. "
                f"{value:02X} << 1 = "
                f"{result:02X}"
            )

        if coefficient == 0x03:

            times_two = aes_mul2(
                value
            )

            result = (
                times_two ^ value
            )

            return (
                f"03 × {value:02X} = "
                f"(02 × {value:02X}) XOR "
                f"{value:02X} = "
                f"{times_two:02X} XOR "
                f"{value:02X} = "
                f"{result:02X}"
            )

        return ""

    # --------------------------------------------------------
    # UPDATE EQUATION
    # --------------------------------------------------------

    def update_equation():

        if not mixcolumns_indices:
            return

        step_index = (
            mixcolumns_indices[
                current_round_position[0]
            ]
        )

        before = (
            aes_steps[step_index - 1]["state"]
        )

        after = (
            aes_steps[step_index]["state"]
        )

        col = selected_column[0]
        output_row = selected_output_row[0]

        input_values = [
            int(before[row][col], 16)
            for row in range(4)
        ]

        coefficients = (
            mix_matrix[output_row]
        )

        products = []

        for coefficient, value in zip(
            coefficients,
            input_values
        ):

            products.append(
                aes_gf_multiply(
                    coefficient,
                    value
                )
            )

        calculated = (
            products[0]
            ^ products[1]
            ^ products[2]
            ^ products[3]
        )

        backend_value = int(
            after[output_row][col],
            16
        )

        lines = []

        lines.append(
            f"Selected output: "
            f"State[{output_row}][{col}]"
        )

        lines.append("")

        lines.append(
            "Input column: "
            + " ".join(
                f"{value:02X}"
                for value in input_values
            )
        )

        lines.append(
            "Matrix row:  "
            + " ".join(
                f"{value:02X}"
                for value in coefficients
            )
        )

        lines.append("")

        symbolic_terms = []

        for coefficient, value in zip(
            coefficients,
            input_values
        ):

            symbolic_terms.append(
                f"({coefficient:02X}×"
                f"{value:02X})"
            )

        lines.append(
            f"b{output_row} = "
            + " XOR ".join(
                symbolic_terms
            )
        )

        lines.append("")

        for coefficient, value in zip(
            coefficients,
            input_values
        ):

            lines.append(
                multiplication_explanation(
                    coefficient,
                    value
                )
            )

        lines.append("")

        lines.append(
            "Products: "
            + " XOR ".join(
                f"{product:02X}"
                for product in products
            )
        )

        lines.append("")

        lines.append(
            "Final XOR:"
        )

        running = products[0]

        lines.append(
            f"Start = {running:02X}"
        )

        for product in products[1:]:

            previous = running

            running ^= product

            lines.append(
                f"{previous:02X} XOR "
                f"{product:02X} = "
                f"{running:02X}"
            )

        lines.append("")

        lines.append(
            f"Calculated output = "
            f"{calculated:02X}"
        )

        lines.append(
            f"AES backend output = "
            f"{backend_value:02X}"
        )

        lines.append("")

        if calculated == backend_value:

            lines.append(
                "Verification: MATCH ✓"
            )

        else:

            lines.append(
                "Verification: MISMATCH"
            )

        equation_text.config(
            state="normal"
        )

        equation_text.delete(
            "1.0",
            tk.END
        )

        equation_text.insert(
            tk.END,
            "\n".join(lines)
        )

        equation_text.config(
            state="disabled"
        )

        # Selected output button

        for row, button in enumerate(
            output_buttons
        ):

            button.config(
                relief=(
                    "sunken"
                    if row == output_row
                    else "raised"
                )
            )

    # --------------------------------------------------------
    # UPDATE SELECTED COLUMN
    # --------------------------------------------------------

    def update_column_analysis():

        if not mixcolumns_indices:
            return

        step_index = (
            mixcolumns_indices[
                current_round_position[0]
            ]
        )

        before = (
            aes_steps[step_index - 1]["state"]
        )

        after = (
            aes_steps[step_index]["state"]
        )

        col = selected_column[0]

        input_column = [
            before[row][col]
            for row in range(4)
        ]

        output_column = [
            after[row][col]
            for row in range(4)
        ]

        # Reset matrix appearance

        for row in range(4):

            for column in range(4):

                before_buttons[row][column].config(
                    relief="raised"
                )

                after_labels[row][column].config(
                    relief="solid"
                )

        # Mark selected column

        for row in range(4):

            before_buttons[row][col].config(
                relief="sunken"
            )

            after_labels[row][col].config(
                relief="sunken"
            )

        column_label.config(
            text=(
                f"Column {col}\n"
                f"Input : ["
                + "  ".join(input_column)
                + "]ᵀ\n"
                f"Output: ["
                + "  ".join(output_column)
                + "]ᵀ"
            )
        )

        update_equation()

    # --------------------------------------------------------
    # DISPLAY ROUND
    # --------------------------------------------------------

    def display_mixcolumns_round(
        position
    ):

        if not mixcolumns_indices:
            return

        if (
            position < 0
            or position >= len(
                mixcolumns_indices
            )
        ):
            return

        current_round_position[0] = (
            position
        )

        step_index = (
            mixcolumns_indices[position]
        )

        before = (
            aes_steps[step_index - 1]["state"]
        )

        after = (
            aes_steps[step_index]["state"]
        )

        round_number = (
            aes_steps[step_index]["round"]
        )

        for row in range(4):

            for col in range(4):

                before_buttons[row][col].config(
                    text=before[row][col]
                )

                after_labels[row][col].config(
                    text=after[row][col]
                )

        round_label.config(
            text=(
                f"Round {round_number} — "
                f"MixColumns "
                f"({position + 1} / "
                f"{len(mixcolumns_indices)})"
            )
        )

        round_scale.set(
            position + 1
        )

        previous_round_button.config(
            state=(
                tk.NORMAL
                if position > 0
                else tk.DISABLED
            )
        )

        next_round_button.config(
            state=(
                tk.NORMAL
                if position <
                len(mixcolumns_indices) - 1
                else tk.DISABLED
            )
        )

        update_column_analysis()

    # --------------------------------------------------------
    # RUN AES
    # --------------------------------------------------------

    def run_aes():

        plaintext_hex = (
            plaintext_entry.get()
            .replace(" ", "")
            .strip()
        )

        key_hex = (
            key_entry.get()
            .replace(" ", "")
            .strip()
        )

        if (
            len(plaintext_hex) != 32
            or len(key_hex) != 32
        ):

            messagebox.showwarning(
                "Invalid AES-128 Input",
                (
                    "Plaintext and key must each "
                    "contain exactly 32 hexadecimal "
                    "characters."
                )
            )

            return

        try:

            bytes.fromhex(plaintext_hex)
            bytes.fromhex(key_hex)

        except ValueError:

            messagebox.showwarning(
                "Invalid Hexadecimal",
                (
                    "Plaintext and key must contain "
                    "hexadecimal characters only."
                )
            )

            return

        try:

            response = requests.post(
                f"{API_URL}/aes/visualize",
                json={
                    "plaintext_hex":
                        plaintext_hex,
                    "key_hex":
                        key_hex
                },
                timeout=10
            )

            response.raise_for_status()

            data = response.json()

            aes_steps.clear()

            aes_steps.extend(
                data["steps"]
            )

            mixcolumns_indices.clear()

            for index, step in enumerate(
                aes_steps
            ):

                if (
                    step["operation"]
                    == "MixColumns"
                ):

                    mixcolumns_indices.append(
                        index
                    )

            # AES-128 has MixColumns only
            # in rounds 1 through 9.

            if len(mixcolumns_indices) != 9:

                messagebox.showwarning(
                    "Unexpected AES Data",
                    (
                        "Expected 9 MixColumns "
                        "transformations but received "
                        f"{len(mixcolumns_indices)}."
                    )
                )

                return

            round_scale.config(
                from_=1,
                to=len(
                    mixcolumns_indices
                )
            )

            selected_column[0] = 0
            selected_output_row[0] = 0

            display_mixcolumns_round(
                0
            )

        except requests.exceptions.ConnectionError:

            messagebox.showerror(
                "Docker API Error",
                (
                    "Cannot connect to the AES "
                    "backend.\n\n"
                    "Check that crypto-api-container "
                    "is running."
                )
            )

        except Exception as e:

            messagebox.showerror(
                "AES Error",
                str(e)
            )

    # --------------------------------------------------------
    # RUN BUTTON
    # --------------------------------------------------------

    run_button = tk.Button(
        input_frame,
        text="RUN AES",
        command=run_aes,
        width=12,
        font=("Arial", 10, "bold")
    )

    run_button.grid(
        row=1,
        column=2,
        padx=10
    )

    # --------------------------------------------------------
    # ROUND NAVIGATION
    # --------------------------------------------------------

    def previous_round():

        display_mixcolumns_round(
            current_round_position[0] - 1
        )

    def next_round():

        display_mixcolumns_round(
            current_round_position[0] + 1
        )

    def jump_round(value):

        if not mixcolumns_indices:
            return

        position = (
            int(float(value)) - 1
        )

        if (
            position
            != current_round_position[0]
        ):

            display_mixcolumns_round(
                position
            )

    navigation_frame = tk.Frame(
        lab
    )

    navigation_frame.pack(
        pady=4
    )

    previous_round_button = tk.Button(
        navigation_frame,
        text="◀ Previous Round",
        command=previous_round,
        width=16,
        state=tk.DISABLED
    )

    previous_round_button.pack(
        side="left",
        padx=8
    )

    next_round_button = tk.Button(
        navigation_frame,
        text="Next Round ▶",
        command=next_round,
        width=16,
        state=tk.DISABLED
    )

    next_round_button.pack(
        side="left",
        padx=8
    )

    round_scale = tk.Scale(
        lab,
        from_=1,
        to=9,
        orient="horizontal",
        length=500,
        command=jump_round,
        showvalue=True,
        tickinterval=1
    )

    round_scale.pack(
        pady=(0, 6)
    )

# ============================================================
# PHASE 7F — ADDROUNDKEY / XOR LABORATORY
# ============================================================

def open_addroundkey_lab():

    lab = tk.Toplevel(root)

    lab.title(
        "AES-128 AddRoundKey & XOR Laboratory"
    )

    lab.geometry(
        "1180x800"
    )

    lab.minsize(
        1000,
        680
    )

    aes_steps = []
    addroundkey_indices = []

    current_position = [0]
    selected_row = [0]
    selected_col = [0]

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    tk.Label(
        lab,
        text="AES-128 AddRoundKey & XOR Laboratory",
        font=("Arial", 21, "bold")
    ).pack(
        pady=(10, 2)
    )

    tk.Label(
        lab,
        text=(
            "Explore how AES combines the state "
            "with each 128-bit round key using XOR"
        ),
        font=("Arial", 11)
    ).pack(
        pady=(0, 7)
    )

    # --------------------------------------------------------
    # INPUT
    # --------------------------------------------------------

    input_frame = tk.LabelFrame(
        lab,
        text="AES-128 Input",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=7
    )

    input_frame.pack(
        padx=20,
        pady=4,
        fill="x"
    )

    tk.Label(
        input_frame,
        text="Plaintext:"
    ).grid(
        row=0,
        column=0,
        sticky="w"
    )

    plaintext_entry = tk.Entry(
        input_frame,
        width=36,
        font=("Courier", 10)
    )

    plaintext_entry.grid(
        row=1,
        column=0,
        padx=(0, 15)
    )

    plaintext_entry.insert(
        0,
        "00112233445566778899AABBCCDDEEFF"
    )

    tk.Label(
        input_frame,
        text="Key:"
    ).grid(
        row=0,
        column=1,
        sticky="w"
    )

    key_entry = tk.Entry(
        input_frame,
        width=36,
        font=("Courier", 10)
    )

    key_entry.grid(
        row=1,
        column=1,
        padx=(0, 15)
    )

    key_entry.insert(
        0,
        "000102030405060708090A0B0C0D0E0F"
    )

    # --------------------------------------------------------
    # ROUND INFORMATION
    # --------------------------------------------------------

    round_label = tk.Label(
        lab,
        text="Run AES to load AddRoundKey transformations",
        font=("Arial", 15, "bold")
    )

    round_label.pack(
        pady=(8, 3)
    )

    step_label = tk.Label(
        lab,
        text="",
        font=("Arial", 10)
    )

    step_label.pack()

    # --------------------------------------------------------
    # THREE-MATRIX AREA
    # --------------------------------------------------------

    matrix_area = tk.Frame(
        lab
    )

    matrix_area.pack(
        pady=10
    )

    # BEFORE STATE

    before_frame = tk.LabelFrame(
        matrix_area,
        text="STATE BEFORE",
        font=("Arial", 11, "bold"),
        padx=8,
        pady=8
    )

    before_frame.pack(
        side="left",
        padx=10
    )

    before_buttons = []

    def select_byte(row, col):

        selected_row[0] = row
        selected_col[0] = col

        update_byte_analysis()

    for row in range(4):

        button_row = []

        for col in range(4):

            button = tk.Button(
                before_frame,
                text="--",
                width=4,
                height=2,
                font=("Courier", 13, "bold"),
                command=lambda r=row, c=col:
                    select_byte(r, c)
            )

            button.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            button_row.append(
                button
            )

        before_buttons.append(
            button_row
        )

    # XOR

    tk.Label(
        matrix_area,
        text=" XOR ",
        font=("Arial", 17, "bold")
    ).pack(
        side="left",
        padx=5
    )

    # ROUND KEY

    key_frame = tk.LabelFrame(
        matrix_area,
        text="ROUND KEY",
        font=("Arial", 11, "bold"),
        padx=8,
        pady=8
    )

    key_frame.pack(
        side="left",
        padx=10
    )

    key_labels = []

    for row in range(4):

        label_row = []

        for col in range(4):

            label = tk.Label(
                key_frame,
                text="--",
                width=4,
                height=2,
                relief="solid",
                font=("Courier", 13, "bold")
            )

            label.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            label_row.append(
                label
            )

        key_labels.append(
            label_row
        )

    # EQUALS

    tk.Label(
        matrix_area,
        text=" = ",
        font=("Arial", 20, "bold")
    ).pack(
        side="left",
        padx=5
    )

    # AFTER STATE

    after_frame = tk.LabelFrame(
        matrix_area,
        text="STATE AFTER",
        font=("Arial", 11, "bold"),
        padx=8,
        pady=8
    )

    after_frame.pack(
        side="left",
        padx=10
    )

    after_labels = []

    for row in range(4):

        label_row = []

        for col in range(4):

            label = tk.Label(
                after_frame,
                text="--",
                width=4,
                height=2,
                relief="solid",
                font=("Courier", 13, "bold")
            )

            label.grid(
                row=row,
                column=col,
                padx=2,
                pady=2
            )

            label_row.append(
                label
            )

        after_labels.append(
            label_row
        )

    # --------------------------------------------------------
    # SELECTED BYTE ANALYSIS
    # --------------------------------------------------------

    analysis_frame = tk.LabelFrame(
        lab,
        text="Selected Byte XOR Analysis",
        font=("Arial", 11, "bold"),
        padx=15,
        pady=10
    )

    analysis_frame.pack(
        padx=30,
        pady=5,
        fill="x"
    )

    hex_label = tk.Label(
        analysis_frame,
        text="Run AES and select a byte.",
        font=("Courier", 13, "bold")
    )

    hex_label.pack(
        pady=(2, 6)
    )

    binary_label = tk.Label(
        analysis_frame,
        text="",
        font=("Courier", 12),
        justify="left"
    )

    binary_label.pack()

    verification_label = tk.Label(
        analysis_frame,
        text="",
        font=("Arial", 11, "bold")
    )

    verification_label.pack(
        pady=(6, 2)
    )

    # --------------------------------------------------------
    # XOR PROPERTIES
    # --------------------------------------------------------

    property_frame = tk.LabelFrame(
        lab,
        text="XOR Properties Used by AddRoundKey",
        font=("Arial", 11, "bold"),
        padx=12,
        pady=7
    )

    property_frame.pack(
        padx=30,
        pady=5,
        fill="x"
    )

    tk.Label(
        property_frame,
        text=(
            "A XOR 00 = A     |     "
            "A XOR A = 00     |     "
            "(A XOR K) XOR K = A"
        ),
        font=("Courier", 11),
        justify="center"
    ).pack()

    # --------------------------------------------------------
    # UPDATE SELECTED BYTE
    # --------------------------------------------------------

    def update_byte_analysis():

        if not addroundkey_indices:
            return

        step_index = (
            addroundkey_indices[
                current_position[0]
            ]
        )

        current_step = (
            aes_steps[step_index]
        )

        previous_step = (
            aes_steps[step_index - 1]
        )

        before = previous_step["state"]
        after = current_step["state"]

        round_key = current_step.get(
            "round_key"
        )

        if not round_key:
            return

        row = selected_row[0]
        col = selected_col[0]

        state_hex = before[row][col]
        key_hex = round_key[row][col]
        result_hex = after[row][col]

        state_value = int(
            state_hex,
            16
        )

        key_value = int(
            key_hex,
            16
        )

        backend_value = int(
            result_hex,
            16
        )

        calculated_value = (
            state_value ^ key_value
        )

        # Reset selection

        for r in range(4):

            for c in range(4):

                before_buttons[r][c].config(
                    relief="raised"
                )

                key_labels[r][c].config(
                    relief="solid"
                )

                after_labels[r][c].config(
                    relief="solid"
                )

        # Mark corresponding byte in all three matrices

        before_buttons[row][col].config(
            relief="sunken"
        )

        key_labels[row][col].config(
            relief="sunken"
        )

        after_labels[row][col].config(
            relief="sunken"
        )

        hex_label.config(
            text=(
                f"State[{row}][{col}]:    "
                f"{state_hex} XOR "
                f"{key_hex} = "
                f"{calculated_value:02X}"
            )
        )

        state_binary = (
            f"{state_value:08b}"
        )

        key_binary = (
            f"{key_value:08b}"
        )

        result_binary = (
            f"{calculated_value:08b}"
        )

        binary_label.config(
            text=(
                f"State byte : "
                f"{state_binary}   "
                f"({state_hex})\n"
                f"Round key  : "
                f"{key_binary}   "
                f"({key_hex})\n"
                f"             "
                f"--------\n"
                f"XOR result : "
                f"{result_binary}   "
                f"({calculated_value:02X})"
            )
        )

        if (
            calculated_value
            == backend_value
        ):

            verification_label.config(
                text=(
                    "Calculated XOR matches "
                    "AES backend output ✓"
                )
            )

        else:

            verification_label.config(
                text=(
                    "Calculated XOR does NOT "
                    "match backend output"
                )
            )

    # --------------------------------------------------------
    # DISPLAY ADDROUNDKEY TRANSFORMATION
    # --------------------------------------------------------

    def display_addroundkey(position):

        if not addroundkey_indices:
            return

        if (
            position < 0
            or position >= len(
                addroundkey_indices
            )
        ):
            return

        current_position[0] = position

        step_index = (
            addroundkey_indices[position]
        )

        current_step = (
            aes_steps[step_index]
        )

        previous_step = (
            aes_steps[step_index - 1]
        )

        before = previous_step["state"]
        after = current_step["state"]

        round_key = current_step.get(
            "round_key"
        )

        if not round_key:

            messagebox.showwarning(
                "Missing Round Key",
                (
                    "The selected AddRoundKey step "
                    "does not contain round-key data."
                )
            )

            return

        round_number = (
            current_step["round"]
        )

        for row in range(4):

            for col in range(4):

                before_buttons[row][col].config(
                    text=before[row][col]
                )

                key_labels[row][col].config(
                    text=round_key[row][col]
                )

                after_labels[row][col].config(
                    text=after[row][col]
                )

        if round_number == 0:

            title = (
                "Initial AddRoundKey — Round 0"
            )

        else:

            title = (
                f"Round {round_number} — "
                f"AddRoundKey"
            )

        round_label.config(
            text=(
                f"{title} "
                f"({position + 1} / "
                f"{len(addroundkey_indices)})"
            )
        )

        step_label.config(
            text=(
                f"AES Step "
                f"{step_index + 1} / "
                f"{len(aes_steps)}"
            )
        )

        transformation_scale.set(
            position + 1
        )

        previous_button.config(
            state=(
                tk.NORMAL
                if position > 0
                else tk.DISABLED
            )
        )

        next_button.config(
            state=(
                tk.NORMAL
                if position <
                len(addroundkey_indices) - 1
                else tk.DISABLED
            )
        )

        update_byte_analysis()

    # --------------------------------------------------------
    # RUN AES
    # --------------------------------------------------------

    def run_aes():

        plaintext_hex = (
            plaintext_entry.get()
            .replace(" ", "")
            .strip()
        )

        key_hex = (
            key_entry.get()
            .replace(" ", "")
            .strip()
        )

        if (
            len(plaintext_hex) != 32
            or len(key_hex) != 32
        ):

            messagebox.showwarning(
                "Invalid AES-128 Input",
                (
                    "Plaintext and key must each "
                    "contain exactly 32 hexadecimal "
                    "characters."
                )
            )

            return

        try:

            bytes.fromhex(
                plaintext_hex
            )

            bytes.fromhex(
                key_hex
            )

        except ValueError:

            messagebox.showwarning(
                "Invalid Hexadecimal",
                (
                    "Plaintext and key must contain "
                    "hexadecimal characters only."
                )
            )

            return

        try:

            response = requests.post(
                f"{API_URL}/aes/visualize",
                json={
                    "plaintext_hex":
                        plaintext_hex,
                    "key_hex":
                        key_hex
                },
                timeout=10
            )

            response.raise_for_status()

            data = response.json()

            aes_steps.clear()

            aes_steps.extend(
                data["steps"]
            )

            addroundkey_indices.clear()

            for index, step in enumerate(
                aes_steps
            ):

                if (
                    step["operation"]
                    == "AddRoundKey"
                ):

                    addroundkey_indices.append(
                        index
                    )

            if len(addroundkey_indices) != 11:

                messagebox.showwarning(
                    "Unexpected AES Data",
                    (
                        "Expected 11 AddRoundKey "
                        "transformations but received "
                        f"{len(addroundkey_indices)}."
                    )
                )

                return

            transformation_scale.config(
                from_=1,
                to=len(
                    addroundkey_indices
                )
            )

            selected_row[0] = 0
            selected_col[0] = 0

            display_addroundkey(
                0
            )

        except requests.exceptions.ConnectionError:

            messagebox.showerror(
                "Docker API Error",
                (
                    "Cannot connect to the AES "
                    "backend.\n\n"
                    "Check that crypto-api-container "
                    "is running."
                )
            )

        except Exception as e:

            messagebox.showerror(
                "AES Error",
                str(e)
            )

    # --------------------------------------------------------
    # RUN BUTTON
    # --------------------------------------------------------

    run_button = tk.Button(
        input_frame,
        text="RUN AES",
        command=run_aes,
        width=12,
        font=("Arial", 10, "bold")
    )

    run_button.grid(
        row=1,
        column=2,
        padx=10
    )

    # --------------------------------------------------------
    # NAVIGATION
    # --------------------------------------------------------

    def previous_transformation():

        display_addroundkey(
            current_position[0] - 1
        )

    def next_transformation():

        display_addroundkey(
            current_position[0] + 1
        )

    def jump_transformation(value):

        if not addroundkey_indices:
            return

        position = (
            int(float(value)) - 1
        )

        if (
            position
            != current_position[0]
        ):

            display_addroundkey(
                position
            )

    navigation_frame = tk.Frame(
        lab
    )

    navigation_frame.pack(
        pady=6
    )

    previous_button = tk.Button(
        navigation_frame,
        text="◀ Previous",
        command=previous_transformation,
        width=16,
        state=tk.DISABLED
    )

    previous_button.pack(
        side="left",
        padx=8
    )

    next_button = tk.Button(
        navigation_frame,
        text="Next ▶",
        command=next_transformation,
        width=16,
        state=tk.DISABLED
    )

    next_button.pack(
        side="left",
        padx=8
    )

    transformation_scale = tk.Scale(
        lab,
        from_=1,
        to=11,
        orient="horizontal",
        length=600,
        command=jump_transformation,
        showvalue=True,
        tickinterval=1
    )

    transformation_scale.pack(
        pady=(0, 8)
    )

# ============================================================
# PHASE 7G — TRANSFORMATION LABORATORY HUB
# ============================================================

def open_transformation_hub():

    hub = tk.Toplevel(root)

    hub.title(
        "AES-128 Transformation Laboratory"
    )

    hub.geometry(
        "920x720"
    )

    hub.minsize(
        820,
        650
    )

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    tk.Label(
        hub,
        text="AES-128 Transformation Laboratory",
        font=("Arial", 23, "bold")
    ).pack(
        pady=(18, 3)
    )

    tk.Label(
        hub,
        text=(
            "Explore the four core AES round "
            "transformations in detail"
        ),
        font=("Arial", 12)
    ).pack(
        pady=(0, 5)
    )

    tk.Label(
        hub,
        text=(
            "SubBytes  →  ShiftRows  →  "
            "MixColumns  →  AddRoundKey"
        ),
        font=("Courier", 12, "bold")
    ).pack(
        pady=(2, 15)
    )

    # --------------------------------------------------------
    # GENERAL TRANSFORMATION EXPLORER
    # --------------------------------------------------------

    explorer_frame = tk.LabelFrame(
        hub,
        text="Complete Round Explorer",
        font=("Arial", 12, "bold"),
        padx=15,
        pady=10
    )

    explorer_frame.pack(
        padx=30,
        pady=(0, 12),
        fill="x"
    )

    tk.Label(
        explorer_frame,
        text=(
            "Compare the AES state immediately "
            "before and after every transformation. "
            "Navigate all 40 transformations "
            "across AES-128 encryption."
        ),
        justify="left",
        wraplength=650,
        font=("Arial", 10)
    ).pack(
        side="left",
        padx=(0, 15),
        expand=True,
        fill="x"
    )

    tk.Button(
        explorer_frame,
        text="Open Explorer",
        command=open_transformation_lab,
        width=18,
        font=("Arial", 10, "bold")
    ).pack(
        side="right"
    )

    # --------------------------------------------------------
    # MODULE GRID
    # --------------------------------------------------------

    module_frame = tk.Frame(
        hub
    )

    module_frame.pack(
        padx=25,
        pady=5,
        fill="both",
        expand=True
    )

    module_frame.grid_columnconfigure(
        0,
        weight=1
    )

    module_frame.grid_columnconfigure(
        1,
        weight=1
    )

    # --------------------------------------------------------
    # HELPER FOR MODULE CARDS
    # --------------------------------------------------------

    def create_module_card(
        row,
        column,
        title,
        subtitle,
        detail,
        command
    ):

        card = tk.LabelFrame(
            module_frame,
            text=title,
            font=("Arial", 12, "bold"),
            padx=12,
            pady=10
        )

        card.grid(
            row=row,
            column=column,
            padx=10,
            pady=10,
            sticky="nsew"
        )

        tk.Label(
            card,
            text=subtitle,
            font=("Arial", 10, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            card,
            text=detail,
            justify="left",
            wraplength=330,
            font=("Arial", 10)
        ).pack(
            anchor="w",
            pady=(5, 10)
        )

        tk.Button(
            card,
            text="Open Laboratory",
            command=command,
            width=18,
            font=("Arial", 10, "bold")
        ).pack(
            anchor="center"
        )

    # --------------------------------------------------------
    # SUBBYTES
    # --------------------------------------------------------

    create_module_card(
        0,
        0,
        "1. SubBytes & S-Box",
        "Non-linear byte substitution",
        (
            "Inspect all 10 SubBytes rounds, "
            "select individual state bytes, "
            "split hexadecimal nibbles and trace "
            "the lookup through the full "
            "16 × 16 AES S-box."
        ),
        open_subbytes_lab
    )

    # --------------------------------------------------------
    # SHIFTROWS
    # --------------------------------------------------------

    create_module_card(
        0,
        1,
        "2. ShiftRows",
        "Cyclic row permutation",
        (
            "Observe the 0, 1, 2 and 3-byte "
            "left rotations and trace each byte "
            "from its original state coordinate "
            "to its destination coordinate."
        ),
        open_shiftrows_lab
    )

    # --------------------------------------------------------
    # MIXCOLUMNS
    # --------------------------------------------------------

    create_module_card(
        1,
        0,
        "3. MixColumns & GF(2⁸)",
        "Finite-field column diffusion",
        (
            "Explore all nine MixColumns rounds, "
            "select columns and output bytes, "
            "and calculate ×01, ×02 and ×03 "
            "operations over GF(2⁸)."
        ),
        open_mixcolumns_lab
    )

    # --------------------------------------------------------
    # ADDROUNDKEY
    # --------------------------------------------------------

    create_module_card(
        1,
        1,
        "4. AddRoundKey & XOR",
        "Key-dependent state transformation",
        (
            "Inspect all 11 AddRoundKey "
            "operations and compare state, "
            "round key and result using both "
            "hexadecimal and binary XOR."
        ),
        open_addroundkey_lab
    )

    # --------------------------------------------------------
    # ROUND STRUCTURE
    # --------------------------------------------------------

    structure_frame = tk.LabelFrame(
        hub,
        text="AES-128 Round Structure",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=7
    )

    structure_frame.pack(
        padx=30,
        pady=(5, 12),
        fill="x"
    )

    tk.Label(
        structure_frame,
        text=(
            "Initial: AddRoundKey     |     "
            "Rounds 1–9: SubBytes → ShiftRows → "
            "MixColumns → AddRoundKey     |     "
            "Round 10: SubBytes → ShiftRows → "
            "AddRoundKey"
        ),
        wraplength=820,
        justify="center",
        font=("Arial", 9)
    ).pack()

# ============================================================
# PHASE 8B — AES-128 KEY EXPANSION LABORATORY
# ============================================================

def open_key_expansion_lab():

    lab = tk.Toplevel(root)
    lab.title("AES-128 Key Expansion Laboratory")
    lab.geometry("1180x820")
    lab.minsize(1000, 700)

    # ========================================================
    # SCROLLABLE CANVAS
    # ========================================================

    canvas = tk.Canvas(
        lab,
        highlightthickness=0
    )

    scrollbar = tk.Scrollbar(
        lab,
        orient="vertical",
        command=canvas.yview
    )

    content = tk.Frame(canvas)

    content_window = canvas.create_window(
        (0, 0),
        window=content,
        anchor="nw"
    )

    canvas.configure(
        yscrollcommand=scrollbar.set
    )

    canvas.pack(
        side="left",
        fill="both",
        expand=True
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    def update_scroll_region(event=None):

        canvas.configure(
            scrollregion=canvas.bbox("all")
        )

    def resize_content(event):

        canvas.itemconfigure(
            content_window,
            width=event.width
        )

    content.bind(
        "<Configure>",
        update_scroll_region
    )

    canvas.bind(
        "<Configure>",
        resize_content
    )

    # --------------------------------------------------------
    # MACOS TRACKPAD / MOUSE WHEEL SCROLLING
    # --------------------------------------------------------

    def close_lab():

        lab.unbind_all(
            "<MouseWheel>"
        )

        lab.destroy()

    lab.protocol(
        "WM_DELETE_WINDOW",
        close_lab
    )

    # ========================================================
    # DATA
    # ========================================================

    expansion_data = {}
    selected_word = [4]
    selected_round = [1]

    word_buttons = []
    round_buttons = []

    # ========================================================
    # TITLE
    # ========================================================

    tk.Label(
        content,
        text="AES-128 Key Expansion Laboratory",
        font=("Arial", 22, "bold")
    ).pack(
        pady=(18, 3)
    )

    tk.Label(
        content,
        text=(
            "Explore the AES-128 key schedule: "
            "44 words → 11 round keys"
        ),
        font=("Arial", 12)
    ).pack(
        pady=(0, 5)
    )

    tk.Label(
        content,
        text=(
            "AES-128 uses one 128-bit original key "
            "to derive ten additional 128-bit round keys."
        ),
        font=("Arial", 10)
    ).pack(
        pady=(0, 15)
    )

    # ========================================================
    # INPUT KEY
    # ========================================================

    input_frame = tk.LabelFrame(
        content,
        text="Original AES-128 Key",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=8
    )

    input_frame.pack(
        padx=25,
        pady=5,
        fill="x"
    )

    tk.Label(
        input_frame,
        text="128-bit Key (32 hex characters):",
        font=("Arial", 10)
    ).grid(
        row=0,
        column=0,
        padx=5,
        pady=5,
        sticky="w"
    )

    key_entry = tk.Entry(
        input_frame,
        width=40,
        font=("Courier", 12)
    )

    key_entry.grid(
        row=0,
        column=1,
        padx=8,
        pady=5
    )

    key_entry.insert(
        0,
        "000102030405060708090A0B0C0D0E0F"
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    summary_label = tk.Label(
        content,
        text=(
            "Enter a key and run the AES-128 "
            "key expansion."
        ),
        font=("Arial", 10, "bold")
    )

    summary_label.pack(
        pady=(5, 10)
    )

    # ========================================================
    # WORD SCHEDULE
    # ========================================================

    schedule_frame = tk.LabelFrame(
        content,
        text="Expanded Key Schedule — W0 to W43",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=10
    )

    schedule_frame.pack(
        padx=25,
        pady=8,
        fill="x"
    )

    tk.Label(
        schedule_frame,
        text=(
            "Select any word to inspect how it "
            "was produced."
        ),
        font=("Arial", 10)
    ).grid(
        row=0,
        column=0,
        columnspan=4,
        pady=(0, 8)
    )

    word_value_labels = []

    for i in range(44):

        row = (i // 4) + 1
        column = i % 4

        cell = tk.Frame(
            schedule_frame,
            padx=4,
            pady=4
        )

        cell.grid(
            row=row,
            column=column,
            padx=5,
            pady=4,
            sticky="nsew"
        )

        button = tk.Button(
            cell,
            text=f"W{i}",
            width=6,
            command=lambda index=i:
                select_word(index)
        )

        button.pack()

        value_label = tk.Label(
            cell,
            text="--------",
            font=("Courier", 10)
        )

        value_label.pack(
            pady=(2, 0)
        )

        word_buttons.append(
            button
        )

        word_value_labels.append(
            value_label
        )

    for c in range(4):

        schedule_frame.grid_columnconfigure(
            c,
            weight=1
        )

    # ========================================================
    # WORD DERIVATION PANEL
    # ========================================================

    derivation_frame = tk.LabelFrame(
        content,
        text="Selected Word Derivation",
        font=("Arial", 12, "bold"),
        padx=12,
        pady=10
    )

    derivation_frame.pack(
        padx=25,
        pady=8,
        fill="x"
    )

    selected_word_label = tk.Label(
        derivation_frame,
        text="Select a word",
        font=("Arial", 15, "bold")
    )

    selected_word_label.pack(
        pady=(0, 5)
    )

    derivation_type_label = tk.Label(
        derivation_frame,
        text="",
        font=("Arial", 10, "bold")
    )

    derivation_type_label.pack(
        pady=(0, 8)
    )

    derivation_text = scrolledtext.ScrolledText(
        derivation_frame,
        width=100,
        height=14,
        font=("Courier", 11),
        wrap="word"
    )

    derivation_text.pack(
        fill="x",
        padx=5,
        pady=5
    )

    derivation_text.configure(
        state="disabled"
    )

    # ========================================================
    # ROUND KEYS
    # ========================================================

    round_frame = tk.LabelFrame(
        content,
        text="AES-128 Round Keys",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=10
    )

    round_frame.pack(
        padx=25,
        pady=8,
        fill="x"
    )

    round_button_frame = tk.Frame(
        round_frame
    )

    round_button_frame.pack(
        pady=(0, 10)
    )

    for i in range(11):

        button = tk.Button(
            round_button_frame,
            text=f"Round {i}",
            width=8,
            command=lambda r=i:
                display_round_key(r)
        )

        button.grid(
            row=i // 6,
            column=i % 6,
            padx=4,
            pady=4
        )

        round_buttons.append(
            button
        )

    round_title_label = tk.Label(
        round_frame,
        text="",
        font=("Arial", 13, "bold")
    )

    round_title_label.pack(
        pady=(3, 5)
    )

    round_words_label = tk.Label(
        round_frame,
        text="",
        font=("Courier", 11)
    )

    round_words_label.pack(
        pady=3
    )

    round_hex_label = tk.Label(
        round_frame,
        text="",
        font=("Courier", 11, "bold")
    )

    round_hex_label.pack(
        pady=3
    )

    # --------------------------------------------------------
    # ROUND KEY MATRIX
    # --------------------------------------------------------

    matrix_frame = tk.Frame(
        round_frame
    )

    matrix_frame.pack(
        pady=8
    )

    round_matrix_labels = []

    for r in range(4):

        matrix_row = []

        for c in range(4):

            label = tk.Label(
                matrix_frame,
                text="--",
                width=5,
                height=2,
                relief="ridge",
                borderwidth=2,
                font=("Courier", 12, "bold")
            )

            label.grid(
                row=r,
                column=c,
                padx=2,
                pady=2
            )

            matrix_row.append(
                label
            )

        round_matrix_labels.append(
            matrix_row
        )

    # ========================================================
    # TEACHING NOTE
    # ========================================================

    teaching_frame = tk.LabelFrame(
        content,
        text="Key Expansion Principle",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=8
    )

    teaching_frame.pack(
        padx=25,
        pady=(8, 20),
        fill="x"
    )

    tk.Label(
        teaching_frame,
        text=(
            "Every fourth generated word uses the AES key-schedule "
            "core: RotWord → SubWord → Rcon. The remaining words "
            "are generated by XOR. AES-128 therefore expands "
            "4 original words into 44 words, forming 11 round keys."
        ),
        wraplength=1000,
        justify="left",
        font=("Arial", 10)
    ).pack()

    # ========================================================
    # HELPERS
    # ========================================================

    def set_derivation_text(text):

        derivation_text.configure(
            state="normal"
        )

        derivation_text.delete(
            "1.0",
            tk.END
        )

        derivation_text.insert(
            tk.END,
            text
        )

        derivation_text.configure(
            state="disabled"
        )

    def xor_word_lines(left_hex, right_hex):

        left = [
            int(left_hex[i:i + 2], 16)
            for i in range(0, 8, 2)
        ]

        right = [
            int(right_hex[i:i + 2], 16)
            for i in range(0, 8, 2)
        ]

        result = [
            left[i] ^ right[i]
            for i in range(4)
        ]

        return "".join(
            f"{value:02X}"
            for value in result
        )

    # ========================================================
    # SELECT WORD
    # ========================================================

    def select_word(index):

        if not expansion_data:
            return

        selected_word[0] = index

        for i, button in enumerate(
            word_buttons
        ):

            button.configure(
                relief=(
                    "sunken"
                    if i == index
                    else "raised"
                )
            )

        derivation = (
            expansion_data[
                "derivations"
            ][index]
        )

        word_name = derivation[
            "word_name"
        ]

        result = derivation[
            "result"
        ]

        selected_word_label.configure(
            text=f"{word_name} = {result}"
        )

        # ====================================================
        # ORIGINAL WORD W0-W3
        # ====================================================

        if derivation["type"] == "original_key":

            derivation_type_label.configure(
                text="Original Key Word"
            )

            start_byte = index * 4
            end_byte = start_byte + 3

            text = (
                f"{word_name} is taken directly from "
                f"the original AES-128 key.\n\n"
                f"Original key byte positions:\n"
                f"Bytes {start_byte} to {end_byte}\n\n"
                f"{word_name} = {result}\n\n"
                f"No RotWord, SubWord or Rcon operation "
                f"is required for W0-W3."
            )

        # ====================================================
        # KEY-SCHEDULE CORE WORD
        # ====================================================

        elif derivation["type"] == "core":

            derivation_type_label.configure(
                text=(
                    "Key-Schedule Core Word "
                    "(i mod 4 = 0)"
                )
            )

            previous = derivation[
                "previous_word"
            ]

            four_back = derivation[
                "four_back_word"
            ]

            rotword = derivation[
                "rotword"
            ]

            subword = derivation[
                "subword"
            ]

            rcon = derivation[
                "rcon"
            ]

            g_result = derivation[
                "g_result"
            ]

            independent_g = xor_word_lines(
                subword,
                rcon
            )

            independent_result = xor_word_lines(
                four_back,
                g_result
            )

            verification = (
                "MATCH ✓"
                if independent_result == result
                and independent_g == g_result
                else "MISMATCH ✗"
            )

            text = (
                f"Deriving {word_name}\n"
                f"{'=' * 62}\n\n"

                f"1. Previous word\n"
                f"   W{index - 1} = {previous}\n\n"

                f"2. RotWord(W{index - 1})\n"
                f"   {previous} → {rotword}\n\n"

                f"3. SubWord\n"
                f"   {rotword} → {subword}\n\n"

                f"4. Round constant\n"
                f"   Rcon = {rcon}\n\n"

                f"5. Apply Rcon\n"
                f"   {subword}\n"
                f" XOR {rcon}\n"
                f" =   {g_result}\n\n"

                f"   g(W{index - 1}) = {g_result}\n\n"

                f"6. Generate {word_name}\n"
                f"   W{index - 4} = {four_back}\n"
                f"   g(...) = {g_result}\n\n"

                f"   {four_back}\n"
                f" XOR {g_result}\n"
                f" =   {result}\n\n"

                f"{word_name} = {result}\n\n"

                f"Independent verification: "
                f"{verification}"
            )

        # ====================================================
        # ORDINARY XOR WORD
        # ====================================================

        else:

            derivation_type_label.configure(
                text="Ordinary XOR Word"
            )

            previous = derivation[
                "previous_word"
            ]

            four_back = derivation[
                "four_back_word"
            ]

            calculated = xor_word_lines(
                four_back,
                previous
            )

            verification = (
                "MATCH ✓"
                if calculated == result
                else "MISMATCH ✗"
            )

            text = (
                f"Deriving {word_name}\n"
                f"{'=' * 62}\n\n"

                f"AES-128 rule:\n\n"

                f"   W{index - 4} XOR "
		f"W{index - 1} = "
		f"W{index}\n\n"
                f"   W{index - 4} = {four_back}\n"
                f"   W{index - 1} = {previous}\n\n"

                f"   {four_back}\n"
                f" XOR {previous}\n"
                f" =   {result}\n\n"

                f"{word_name} = {result}\n\n"

                f"Independent calculation = "
                f"{calculated}\n"
                f"Backend result          = "
                f"{result}\n\n"

                f"{verification}\n\n"

                f"RotWord: NOT used\n"
                f"SubWord: NOT used\n"
                f"Rcon:    NOT used"
            )

        set_derivation_text(
            text
        )

        # Automatically show the round key
        # containing this word.

        round_number = index // 4

        display_round_key(
            round_number
        )

    # ========================================================
    # DISPLAY ROUND KEY
    # ========================================================

    def display_round_key(round_number):

        if not expansion_data:
            return

        selected_round[0] = round_number

        round_key = (
            expansion_data[
                "round_keys"
            ][round_number]
        )

        for i, button in enumerate(
            round_buttons
        ):

            button.configure(
                relief=(
                    "sunken"
                    if i == round_number
                    else "raised"
                )
            )

        round_title_label.configure(
            text=(
                f"Round Key {round_number}"
            )
        )

        round_words_label.configure(
            text=(
                "Words: "
                + "   ".join(
                    round_key["words"]
                )
            )
        )

        round_hex_label.configure(
            text=(
                "128-bit key: "
                + round_key["key_hex"]
            )
        )

        matrix = round_key[
            "matrix"
        ]

        for r in range(4):

            for c in range(4):

                round_matrix_labels[
                    r
                ][c].configure(
                    text=matrix[r][c]
                )

    # ========================================================
    # RUN KEY EXPANSION
    # ========================================================

    def run_key_expansion():

        key_hex = (
            key_entry
            .get()
            .replace(" ", "")
            .strip()
        )

        if len(key_hex) != 32:

            messagebox.showerror(
                "Invalid AES-128 Key",
                (
                    "The key must contain exactly "
                    "32 hexadecimal characters "
                    "(16 bytes / 128 bits)."
                )
            )

            return

        try:

            bytes.fromhex(
                key_hex
            )

        except ValueError:

            messagebox.showerror(
                "Invalid AES-128 Key",
                (
                    "The key must contain hexadecimal "
                    "characters only."
                )
            )

            return

        try:

            response = requests.post(
                "http://localhost:8000/aes/key-expansion",
                json={
                    "key_hex": key_hex
                },
                timeout=10
            )

            response.raise_for_status()

            data = response.json()

        except Exception as e:

            messagebox.showerror(
                "Backend Error",
                str(e)
            )

            return

        expansion_data.clear()
        expansion_data.update(
            data
        )

        if (
            expansion_data.get(
                "total_words"
            ) != 44
        ):

            messagebox.showerror(
                "Key Schedule Error",
                (
                    "Expected 44 expanded words "
                    "for AES-128."
                )
            )

            return

        if (
            expansion_data.get(
                "total_round_keys"
            ) != 11
        ):

            messagebox.showerror(
                "Key Schedule Error",
                (
                    "Expected 11 round keys "
                    "for AES-128."
                )
            )

            return

        words = expansion_data[
            "words"
        ]

        for i in range(44):

            word_value_labels[
                i
            ].configure(
                text=words[i]["hex"]
            )

        summary_label.configure(
            text=(
                "AES-128 Key Expansion Complete: "
                "4 original words → "
                "44 expanded words → "
                "11 round keys"
            )
        )

        # W4 is the best first teaching example.
        select_word(
            4
        )

    # ========================================================
    # RUN BUTTON
    # ========================================================

    tk.Button(
        input_frame,
        text="RUN KEY EXPANSION",
        command=run_key_expansion,
        font=("Arial", 10, "bold"),
        width=20
    ).grid(
        row=0,
        column=2,
        padx=8,
        pady=5
    )

# ============================================================
# PHASE 9B — AES-128 AVALANCHE LABORATORY
# ============================================================

def open_avalanche_lab():

    lab = tk.Toplevel(root)
    lab.title("AES-128 Avalanche Laboratory")
    lab.geometry("1220x850")
    lab.minsize(1050, 720)

    # ========================================================
    # SCROLLABLE WINDOW
    # ========================================================

    canvas = tk.Canvas(
        lab,
        highlightthickness=0
    )

    scrollbar = tk.Scrollbar(
        lab,
        orient="vertical",
        command=canvas.yview,
        width=20
    )

    # --------------------------------------------------------
    # KEYBOARD SCROLLING
    # --------------------------------------------------------

    def scroll_up(event=None):

        canvas.yview_scroll(
            -3,
            "units"
        )

        return "break"

    def scroll_down(event=None):

        canvas.yview_scroll(
            3,
            "units"
        )

        return "break"

    def page_up(event=None):

        canvas.yview_scroll(
            -1,
            "pages"
        )

        return "break"

    def page_down(event=None):

        canvas.yview_scroll(
            1,
            "pages"
        )

        return "break"

    def scroll_home(event=None):

        canvas.yview_moveto(0)

        return "break"

    def scroll_end(event=None):

        canvas.yview_moveto(1)

        return "break"

    lab.bind(
        "<Up>",
        scroll_up
    )

    lab.bind(
        "<Down>",
        scroll_down
    )

    lab.bind(
        "<Prior>",
        page_up
    )

    lab.bind(
        "<Next>",
        page_down
    )

    lab.bind(
        "<Home>",
        scroll_home
    )

    lab.bind(
        "<End>",
        scroll_end
    )

    content = tk.Frame(canvas)

    content_window = canvas.create_window(
        (0, 0),
        window=content,
        anchor="nw"
    )

    canvas.configure(
        yscrollcommand=scrollbar.set
    )

    canvas.pack(
        side="left",
        fill="both",
        expand=True
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    def update_scroll_region(event=None):
        canvas.configure(
            scrollregion=canvas.bbox("all")
        )

    def resize_content(event):
        canvas.itemconfigure(
            content_window,
            width=event.width
        )

    content.bind(
        "<Configure>",
        update_scroll_region
    )

    canvas.bind(
        "<Configure>",
        resize_content
    )

    def mousewheel(event):
        canvas.yview_scroll(
            int(-1 * (event.delta / 120)),
            "units"
        )

    canvas.bind_all(
        "<MouseWheel>",
        mousewheel
    )

    # ========================================================
    # DATA
    # ========================================================

    avalanche_data = {}
    selected_step = [0]

    # ========================================================
    # TITLE
    # ========================================================

    tk.Label(
        content,
        text="AES-128 Avalanche Laboratory",
        font=("Arial", 22, "bold")
    ).pack(
        pady=(18, 3)
    )

    tk.Label(
        content,
        text=(
            "Change exactly one plaintext or key bit and "
            "observe how the difference propagates through AES-128."
        ),
        font=("Arial", 11)
    ).pack(
        pady=(0, 15)
    )

    scroll_control_frame = tk.Frame(
        content
    )

    scroll_control_frame.pack(
        pady=(0, 8)
    )

    tk.Button(
        scroll_control_frame,
        text="▲ Scroll Up",
        width=14,
        command=lambda: canvas.yview_scroll(
            -4,
            "units"
        )
    ).pack(
        side="left",
        padx=5
    )

    tk.Button(
        scroll_control_frame,
        text="▼ Scroll Down",
        width=14,
        command=lambda: canvas.yview_scroll(
            4,
            "units"
        )
    ).pack(
        side="left",
        padx=5
    )

    # ========================================================
    # INPUTS
    # ========================================================

    input_frame = tk.LabelFrame(
        content,
        text="Experiment Configuration",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=10
    )

    input_frame.pack(
        padx=25,
        pady=5,
        fill="x"
    )

    tk.Label(
        input_frame,
        text="Plaintext:",
        font=("Arial", 10)
    ).grid(
        row=0,
        column=0,
        sticky="w",
        padx=5,
        pady=4
    )

    plaintext_entry = tk.Entry(
        input_frame,
        width=40,
        font=("Courier", 11)
    )

    plaintext_entry.grid(
        row=0,
        column=1,
        columnspan=3,
        sticky="w",
        padx=5,
        pady=4
    )

    plaintext_entry.insert(
        0,
        "00112233445566778899AABBCCDDEEFF"
    )

    tk.Label(
        input_frame,
        text="AES-128 Key:",
        font=("Arial", 10)
    ).grid(
        row=1,
        column=0,
        sticky="w",
        padx=5,
        pady=4
    )

    key_entry = tk.Entry(
        input_frame,
        width=40,
        font=("Courier", 11)
    )

    key_entry.grid(
        row=1,
        column=1,
        columnspan=3,
        sticky="w",
        padx=5,
        pady=4
    )

    key_entry.insert(
        0,
        "000102030405060708090A0B0C0D0E0F"
    )

    # --------------------------------------------------------
    # EXPERIMENT TYPE
    # --------------------------------------------------------

    experiment_var = tk.StringVar(
        value="plaintext"
    )

    tk.Label(
        input_frame,
        text="Flip one bit in:",
        font=("Arial", 10, "bold")
    ).grid(
        row=2,
        column=0,
        sticky="w",
        padx=5,
        pady=7
    )

    tk.Radiobutton(
        input_frame,
        text="Plaintext",
        variable=experiment_var,
        value="plaintext"
    ).grid(
        row=2,
        column=1,
        sticky="w"
    )

    tk.Radiobutton(
        input_frame,
        text="AES Key",
        variable=experiment_var,
        value="key"
    ).grid(
        row=2,
        column=2,
        sticky="w"
    )

    # --------------------------------------------------------
    # BIT SELECTOR
    # --------------------------------------------------------

    bit_var = tk.IntVar(
        value=0
    )

    tk.Label(
        input_frame,
        text="Bit index:",
        font=("Arial", 10, "bold")
    ).grid(
        row=3,
        column=0,
        sticky="w",
        padx=5,
        pady=5
    )

    bit_scale = tk.Scale(
        input_frame,
        from_=0,
        to=127,
        orient="horizontal",
        variable=bit_var,
        length=520,
        showvalue=True
    )

    bit_scale.grid(
        row=3,
        column=1,
        columnspan=3,
        sticky="w",
        padx=5
    )

    bit_note_label = tk.Label(
        input_frame,
        text=(
            "Bit 0 = MSB of byte 0   |   "
            "Bit 127 = LSB of byte 15"
        ),
        font=("Arial", 9)
    )

    bit_note_label.grid(
        row=4,
        column=1,
        columnspan=3,
        sticky="w",
        padx=5
    )

    # ========================================================
    # RESULT SUMMARY
    # ========================================================

    summary_frame = tk.LabelFrame(
        content,
        text="Avalanche Result",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=10
    )

    summary_frame.pack(
        padx=25,
        pady=10,
        fill="x"
    )

    experiment_summary_label = tk.Label(
        summary_frame,
        text="Run an experiment to view results.",
        font=("Arial", 11, "bold")
    )

    experiment_summary_label.pack(
        pady=3
    )

    original_value_label = tk.Label(
        summary_frame,
        text="",
        font=("Courier", 10)
    )

    original_value_label.pack(
        pady=2
    )

    modified_value_label = tk.Label(
        summary_frame,
        text="",
        font=("Courier", 10)
    )

    modified_value_label.pack(
        pady=2
    )

    final_result_label = tk.Label(
        summary_frame,
        text="",
        font=("Arial", 13, "bold")
    )

    final_result_label.pack(
        pady=(6, 2)
    )

    ciphertext_label = tk.Label(
        summary_frame,
        text="",
        font=("Courier", 9),
        justify="left"
    )

    ciphertext_label.pack(
        pady=3
    )

    # ========================================================
    # GRAPH
    # ========================================================

    graph_frame = tk.LabelFrame(
        content,
        text="Avalanche Propagation Across 41 AES States",
        font=("Arial", 12, "bold"),
        padx=8,
        pady=8
    )

    graph_frame.pack(
        padx=25,
        pady=10,
        fill="both",
        expand=True
    )

    figure = Figure(
        figsize=(10.5, 4.2),
        dpi=100
    )

    graph_axis = figure.add_subplot(111)

    graph_axis.set_title(
        "Run an avalanche experiment"
    )

    graph_axis.set_xlabel(
        "AES Teaching Step"
    )

    graph_axis.set_ylabel(
        "Hamming Distance (bits)"
    )

    graph_axis.set_xlim(
        1,
        41
    )

    graph_axis.set_ylim(
        0,
        128
    )

    graph_axis.grid(
        True,
        alpha=0.3
    )

    graph_canvas = FigureCanvasTkAgg(
        figure,
        master=graph_frame
    )

    graph_canvas.get_tk_widget().pack(
        fill="both",
        expand=True
    )

    graph_canvas.draw()

    # ========================================================
    # STEP NAVIGATION
    # ========================================================

    navigation_frame = tk.LabelFrame(
        content,
        text="Inspect Individual AES State",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=8
    )

    navigation_frame.pack(
        padx=25,
        pady=10,
        fill="x"
    )

    step_title_label = tk.Label(
        navigation_frame,
        text="No step selected",
        font=("Arial", 13, "bold")
    )

    step_title_label.pack(
        pady=3
    )

    step_statistics_label = tk.Label(
        navigation_frame,
        text="",
        font=("Arial", 11, "bold")
    )

    step_statistics_label.pack(
        pady=3
    )

    nav_controls = tk.Frame(
        navigation_frame
    )

    nav_controls.pack(
        pady=5
    )

    # ========================================================
    # STATE MATRICES
    # ========================================================

    states_frame = tk.Frame(
        content
    )

    states_frame.pack(
        padx=25,
        pady=10
    )

    original_frame = tk.LabelFrame(
        states_frame,
        text="Original AES State",
        font=("Arial", 11, "bold"),
        padx=8,
        pady=8
    )

    original_frame.grid(
        row=0,
        column=0,
        padx=25
    )

    modified_frame = tk.LabelFrame(
        states_frame,
        text="Modified AES State",
        font=("Arial", 11, "bold"),
        padx=8,
        pady=8
    )

    modified_frame.grid(
        row=0,
        column=1,
        padx=25
    )

    original_matrix = []
    modified_matrix = []

    for r in range(4):

        original_row = []
        modified_row = []

        for c in range(4):

            left_label = tk.Label(
                original_frame,
                text="--",
                width=5,
                height=2,
                relief="ridge",
                borderwidth=2,
                font=("Courier", 12, "bold")
            )

            left_label.grid(
                row=r,
                column=c,
                padx=2,
                pady=2
            )

            original_row.append(
                left_label
            )

            right_label = tk.Label(
                modified_frame,
                text="--",
                width=5,
                height=2,
                relief="ridge",
                borderwidth=2,
                font=("Courier", 12, "bold")
            )

            right_label.grid(
                row=r,
                column=c,
                padx=2,
                pady=2
            )

            modified_row.append(
                right_label
            )

        original_matrix.append(
            original_row
        )

        modified_matrix.append(
            modified_row
        )

    # ========================================================
    # DISPLAY SELECTED STEP
    # ========================================================

    def display_step(index):

        if not avalanche_data:
            return

        comparisons = avalanche_data[
            "comparisons"
        ]

        if index < 0 or index >= len(comparisons):
            return

        selected_step[0] = index

        comparison = comparisons[index]

        step_title_label.configure(
            text=(
                f"Step {comparison['step']} / "
                f"{len(comparisons)} — "
                f"Round {comparison['round']} "
                f"{comparison['operation']}"
            )
        )

        step_statistics_label.configure(
            text=(
                f"Hamming Distance: "
                f"{comparison['hamming_distance']} / 128 bits"
                f"     |     "
                f"Avalanche: "
                f"{comparison['avalanche_percentage']:.2f}%"
            )
        )

        original_state = comparison[
            "original_state"
        ]

        modified_state = comparison[
            "modified_state"
        ]

        for r in range(4):

            for c in range(4):

                original_matrix[r][c].configure(
                    text=original_state[r][c]
                )

                modified_matrix[r][c].configure(
                    text=modified_state[r][c]
                )

        step_scale.set(
            index + 1
        )

        previous_button.configure(
            state=(
                "disabled"
                if index == 0
                else "normal"
            )
        )

        next_button.configure(
            state=(
                "disabled"
                if index == len(comparisons) - 1
                else "normal"
            )
        )

        # Highlight selected point on graph.
        update_graph(
            selected_index=index
        )

    # ========================================================
    # GRAPH UPDATE
    # ========================================================

    def update_graph(selected_index=None):

        graph_axis.clear()

        if not avalanche_data:

            graph_axis.set_title(
                "Run an avalanche experiment"
            )

            graph_axis.set_xlabel(
                "AES Teaching Step"
            )

            graph_axis.set_ylabel(
                "Hamming Distance (bits)"
            )

            graph_axis.set_xlim(
                1,
                41
            )

            graph_axis.set_ylim(
                0,
                128
            )

            graph_axis.grid(
                True,
                alpha=0.3
            )

            graph_canvas.draw()

            return

        comparisons = avalanche_data[
            "comparisons"
        ]

        x_values = [
            item["step"]
            for item in comparisons
        ]

        y_values = [
            item["hamming_distance"]
            for item in comparisons
        ]

        graph_axis.plot(
            x_values,
            y_values,
            marker="o",
            markersize=4,
            linewidth=1.5,
            picker=5
        )

        # 50% reference = 64 of 128 bits.
        graph_axis.axhline(
            y=64,
            linestyle="--",
            linewidth=1,
            label="50% of state = 64 bits"
        )

        if selected_index is not None:

            selected = comparisons[
                selected_index
            ]

            graph_axis.scatter(
                [selected["step"]],
                [selected["hamming_distance"]],
                s=90,
                zorder=5
            )

        experiment_name = (
            "Plaintext-bit Avalanche"
            if avalanche_data[
                "experiment_type"
            ] == "plaintext"
            else "Key-bit Avalanche"
        )

        graph_axis.set_title(
            (
                f"{experiment_name} — "
                f"flipped bit "
                f"{avalanche_data['bit_index']}"
            )
        )

        graph_axis.set_xlabel(
            "AES Teaching Step (1–41)"
        )

        graph_axis.set_ylabel(
            "Hamming Distance (bits)"
        )

        graph_axis.set_xlim(
            1,
            41
        )

        graph_axis.set_ylim(
            0,
            128
        )

        graph_axis.set_xticks(
            [1, 5, 10, 15, 20, 25, 30, 35, 41]
        )

        graph_axis.grid(
            True,
            alpha=0.3
        )

        graph_axis.legend(
            loc="best"
        )

        figure.tight_layout()

        graph_canvas.draw()

    # ========================================================
    # CLICK GRAPH POINT
    # ========================================================

    def graph_click(event):

        if not avalanche_data:
            return

        if event.inaxes != graph_axis:
            return

        if event.xdata is None:
            return

        nearest_step = int(
            round(event.xdata)
        )

        nearest_step = max(
            1,
            min(
                41,
                nearest_step
            )
        )

        display_step(
            nearest_step - 1
        )

    graph_canvas.mpl_connect(
        "button_press_event",
        graph_click
    )

    # ========================================================
    # NAVIGATION
    # ========================================================

    def previous_step():

        if selected_step[0] > 0:

            display_step(
                selected_step[0] - 1
            )

    def next_step():

        if not avalanche_data:
            return

        if (
            selected_step[0]
            < len(
                avalanche_data[
                    "comparisons"
                ]
            ) - 1
        ):

            display_step(
                selected_step[0] + 1
            )

    def jump_to_step(value):

        if not avalanche_data:
            return

        index = int(
            float(value)
        ) - 1

        if index != selected_step[0]:

            display_step(
                index
            )

    previous_button = tk.Button(
        nav_controls,
        text="Previous",
        command=previous_step,
        width=12
    )

    previous_button.grid(
        row=0,
        column=0,
        padx=8
    )

    step_scale = tk.Scale(
        nav_controls,
        from_=1,
        to=41,
        orient="horizontal",
        length=600,
        command=jump_to_step,
        showvalue=True,
        tickinterval=5
    )

    step_scale.grid(
        row=0,
        column=1,
        padx=8
    )

    next_button = tk.Button(
        nav_controls,
        text="Next",
        command=next_step,
        width=12
    )

    next_button.grid(
        row=0,
        column=2,
        padx=8
    )

    # ========================================================
    # RUN EXPERIMENT
    # ========================================================

    def run_experiment():

        plaintext_hex = (
            plaintext_entry
            .get()
            .replace(" ", "")
            .strip()
        )

        key_hex = (
            key_entry
            .get()
            .replace(" ", "")
            .strip()
        )

        if len(plaintext_hex) != 32:

            messagebox.showerror(
                "Invalid Plaintext",
                (
                    "Plaintext must contain exactly "
                    "32 hexadecimal characters."
                )
            )

            return

        if len(key_hex) != 32:

            messagebox.showerror(
                "Invalid AES-128 Key",
                (
                    "Key must contain exactly "
                    "32 hexadecimal characters."
                )
            )

            return

        try:

            bytes.fromhex(
                plaintext_hex
            )

            bytes.fromhex(
                key_hex
            )

        except ValueError:

            messagebox.showerror(
                "Invalid Hexadecimal Input",
                (
                    "Plaintext and key must contain "
                    "hexadecimal characters only."
                )
            )

            return

        try:

            response = requests.post(
                "http://localhost:8000/aes/avalanche",
                json={
                    "plaintext_hex":
                        plaintext_hex,
                    "key_hex":
                        key_hex,
                    "experiment_type":
                        experiment_var.get(),
                    "bit_index":
                        bit_var.get()
                },
                timeout=10
            )

            response.raise_for_status()

            data = response.json()

        except Exception as e:

            messagebox.showerror(
                "Backend Error",
                str(e)
            )

            return

        avalanche_data.clear()

        avalanche_data.update(
            data
        )

        if (
            avalanche_data.get(
                "total_steps"
            ) != 41
        ):

            messagebox.showerror(
                "Avalanche Analysis Error",
                (
                    "Expected 41 AES state "
                    "comparisons."
                )
            )

            return

        experiment_type = (
            avalanche_data[
                "experiment_type"
            ]
        )

        bit_index = avalanche_data[
            "bit_index"
        ]

        byte_index = avalanche_data[
            "byte_index"
        ]

        bit_in_byte = avalanche_data[
            "bit_in_byte_from_msb"
        ]

        experiment_summary_label.configure(
            text=(
                f"{experiment_type.upper()} "
                f"AVALANCHE — "
                f"Bit {bit_index} flipped "
                f"(byte {byte_index}, "
                f"bit {bit_in_byte} from MSB)"
            )
        )

        if experiment_type == "plaintext":

            original_value_label.configure(
                text=(
                    "Original plaintext: "
                    + avalanche_data[
                        "original_plaintext_hex"
                    ]
                )
            )

            modified_value_label.configure(
                text=(
                    "Modified plaintext: "
                    + avalanche_data[
                        "modified_plaintext_hex"
                    ]
                )
            )

        else:

            original_value_label.configure(
                text=(
                    "Original key:       "
                    + avalanche_data[
                        "original_key_hex"
                    ]
                )
            )

            modified_value_label.configure(
                text=(
                    "Modified key:       "
                    + avalanche_data[
                        "modified_key_hex"
                    ]
                )
            )

        final_result_label.configure(
            text=(
                "Final Ciphertext Difference: "
                f"{avalanche_data['final_hamming_distance']} "
                "/ 128 bits     |     "
                "Avalanche: "
                f"{avalanche_data['final_avalanche_percentage']:.2f}%"
            )
        )

        ciphertext_label.configure(
            text=(
                "Original ciphertext: "
                + avalanche_data[
                    "original_ciphertext_hex"
                ]
                + "\n"
                + "Modified ciphertext: "
                + avalanche_data[
                    "modified_ciphertext_hex"
                ]
            )
        )

        selected_step[0] = 0

        display_step(
            0
        )

    # ========================================================
    # RUN BUTTON
    # ========================================================

    tk.Button(
        input_frame,
        text="RUN AVALANCHE EXPERIMENT",
        command=run_experiment,
        width=28,
        font=("Arial", 10, "bold")
    ).grid(
        row=5,
        column=0,
        columnspan=4,
        pady=(12, 3)
    )

# ============================================================
# PHASE 10B — STUDENT LAB EXPERIMENT MODE
# ============================================================

def open_lab_experiment_mode():

    lab = tk.Toplevel(root)
    lab.title("AES-128 Student Lab Experiment Mode")
    lab.geometry("1250x850")
    lab.minsize(1050, 720)

    # ========================================================
    # SCROLLABLE PAGE
    # ========================================================

    canvas = tk.Canvas(
        lab,
        highlightthickness=0
    )

    scrollbar = tk.Scrollbar(
        lab,
        orient="vertical",
        command=canvas.yview
    )

    content = tk.Frame(canvas)

    content_window = canvas.create_window(
        (0, 0),
        window=content,
        anchor="nw"
    )

    canvas.configure(
        yscrollcommand=scrollbar.set
    )

    canvas.pack(
        side="left",
        fill="both",
        expand=True
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    def update_scroll_region(event=None):

        canvas.configure(
            scrollregion=canvas.bbox("all")
        )

    def resize_content(event):

        canvas.itemconfigure(
            content_window,
            width=event.width
        )

    content.bind(
        "<Configure>",
        update_scroll_region
    )

    canvas.bind(
        "<Configure>",
        resize_content
    )

    def mousewheel(event):

        canvas.yview_scroll(
            int(-1 * (event.delta / 120)),
            "units"
        )

    canvas.bind_all(
        "<MouseWheel>",
        mousewheel
    )

    # ========================================================
    # STATE
    # ========================================================

    experiment_data = {}

    experiment_var = tk.StringVar(
        value="plaintext"
    )

    range_var = tk.StringVar(
        value="0-7"
    )

    # ========================================================
    # TITLE
    # ========================================================

    tk.Label(
        content,
        text="AES-128 Student Lab Experiment Mode",
        font=("Arial", 22, "bold")
    ).pack(
        pady=(18, 3)
    )

    tk.Label(
        content,
        text=(
            "Formal experimental study of the "
            "AES-128 avalanche effect"
        ),
        font=("Arial", 12)
    ).pack(
        pady=(0, 15)
    )

    # ========================================================
    # EXPERIMENT SELECTION
    # ========================================================

    selection_frame = tk.LabelFrame(
        content,
        text="Select Experiment",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=8
    )

    selection_frame.pack(
        padx=25,
        pady=5,
        fill="x"
    )

    tk.Radiobutton(
        selection_frame,
        text="Experiment 1 — Plaintext Avalanche Effect",
        variable=experiment_var,
        value="plaintext",
        command=lambda:
            update_experiment_information()
    ).pack(
        anchor="w",
        pady=3
    )

    tk.Radiobutton(
        selection_frame,
        text="Experiment 2 — Key Avalanche Effect",
        variable=experiment_var,
        value="key",
        command=lambda:
            update_experiment_information()
    ).pack(
        anchor="w",
        pady=3
    )

    # ========================================================
    # AIM
    # ========================================================

    aim_frame = tk.LabelFrame(
        content,
        text="Aim",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=8
    )

    aim_frame.pack(
        padx=25,
        pady=7,
        fill="x"
    )

    aim_label = tk.Label(
        aim_frame,
        text="",
        wraplength=1100,
        justify="left",
        font=("Arial", 10)
    )

    aim_label.pack(
        anchor="w"
    )

    # ========================================================
    # LEARNING OBJECTIVES
    # ========================================================

    objective_frame = tk.LabelFrame(
        content,
        text="Learning Objectives",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=8
    )

    objective_frame.pack(
        padx=25,
        pady=7,
        fill="x"
    )

    objective_label = tk.Label(
        objective_frame,
        text="",
        wraplength=1100,
        justify="left",
        font=("Arial", 10)
    )

    objective_label.pack(
        anchor="w"
    )

    # ========================================================
    # THEORY
    # ========================================================

    theory_frame = tk.LabelFrame(
        content,
        text="Theory",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=8
    )

    theory_frame.pack(
        padx=25,
        pady=7,
        fill="x"
    )

    theory_label = tk.Label(
        theory_frame,
        text="",
        wraplength=1100,
        justify="left",
        font=("Arial", 10)
    )

    theory_label.pack(
        anchor="w"
    )

    # ========================================================
    # PROCEDURE
    # ========================================================

    procedure_frame = tk.LabelFrame(
        content,
        text="Experimental Procedure",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=8
    )

    procedure_frame.pack(
        padx=25,
        pady=7,
        fill="x"
    )

    procedure_label = tk.Label(
        procedure_frame,
        text="",
        wraplength=1100,
        justify="left",
        font=("Arial", 10)
    )

    procedure_label.pack(
        anchor="w"
    )

    # ========================================================
    # CONFIGURATION
    # ========================================================

    config_frame = tk.LabelFrame(
        content,
        text="Experiment Configuration",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=10
    )

    config_frame.pack(
        padx=25,
        pady=8,
        fill="x"
    )

    tk.Label(
        config_frame,
        text="Plaintext:",
        font=("Arial", 10)
    ).grid(
        row=0,
        column=0,
        sticky="w",
        padx=5,
        pady=4
    )

    plaintext_entry = tk.Entry(
        config_frame,
        width=40,
        font=("Courier", 11)
    )

    plaintext_entry.grid(
        row=0,
        column=1,
        columnspan=4,
        sticky="w",
        padx=5,
        pady=4
    )

    plaintext_entry.insert(
        0,
        "00112233445566778899AABBCCDDEEFF"
    )

    tk.Label(
        config_frame,
        text="AES-128 Key:",
        font=("Arial", 10)
    ).grid(
        row=1,
        column=0,
        sticky="w",
        padx=5,
        pady=4
    )

    key_entry = tk.Entry(
        config_frame,
        width=40,
        font=("Courier", 11)
    )

    key_entry.grid(
        row=1,
        column=1,
        columnspan=4,
        sticky="w",
        padx=5,
        pady=4
    )

    key_entry.insert(
        0,
        "000102030405060708090A0B0C0D0E0F"
    )

    tk.Label(
        config_frame,
        text="Trial range:",
        font=("Arial", 10, "bold")
    ).grid(
        row=2,
        column=0,
        sticky="w",
        padx=5,
        pady=8
    )

    ranges = [
        ("Bits 0–7 (8 trials)", "0-7"),
        ("Bits 0–15 (16 trials)", "0-15"),
        ("Bits 0–31 (32 trials)", "0-31"),
        ("Bits 0–63 (64 trials)", "0-63"),
        ("Bits 0–127 (128 trials)", "0-127")
    ]

    for index, (
        text,
        value
    ) in enumerate(ranges):

        tk.Radiobutton(
            config_frame,
            text=text,
            variable=range_var,
            value=value
        ).grid(
            row=3 + index,
            column=1,
            columnspan=3,
            sticky="w",
            padx=5
        )

    # ========================================================
    # OBSERVATION TABLE
    # ========================================================

    observation_frame = tk.LabelFrame(
        content,
        text="Observation Table",
        font=("Arial", 12, "bold"),
        padx=8,
        pady=8
    )

    observation_frame.pack(
        padx=25,
        pady=10,
        fill="both",
        expand=True
    )

    columns = (
        "trial",
        "bit",
        "byte",
        "bitpos",
        "hd",
        "avalanche"
    )

    observation_tree = ttk.Treeview(
        observation_frame,
        columns=columns,
        show="headings",
        height=12
    )

    observation_tree.heading(
        "trial",
        text="Trial"
    )

    observation_tree.heading(
        "bit",
        text="Flipped Bit"
    )

    observation_tree.heading(
        "byte",
        text="Byte"
    )

    observation_tree.heading(
        "bitpos",
        text="Bit in Byte"
    )

    observation_tree.heading(
        "hd",
        text="Final HD / 128"
    )

    observation_tree.heading(
        "avalanche",
        text="Avalanche %"
    )

    observation_tree.column(
        "trial",
        width=70,
        anchor="center"
    )

    observation_tree.column(
        "bit",
        width=100,
        anchor="center"
    )

    observation_tree.column(
        "byte",
        width=80,
        anchor="center"
    )

    observation_tree.column(
        "bitpos",
        width=100,
        anchor="center"
    )

    observation_tree.column(
        "hd",
        width=120,
        anchor="center"
    )

    observation_tree.column(
        "avalanche",
        width=120,
        anchor="center"
    )

    table_scrollbar = ttk.Scrollbar(
        observation_frame,
        orient="vertical",
        command=observation_tree.yview
    )

    observation_tree.configure(
        yscrollcommand=table_scrollbar.set
    )

    observation_tree.pack(
        side="left",
        fill="both",
        expand=True
    )

    table_scrollbar.pack(
        side="right",
        fill="y"
    )

    # ========================================================
    # EXPERIMENT GRAPH
    # ========================================================

    graph_frame = tk.LabelFrame(
        content,
        text="Experimental Avalanche Graph",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=10
    )

    graph_frame.pack(
        padx=25,
        pady=10,
        fill="both",
        expand=True
    )

    graph_info_label = tk.Label(
        graph_frame,
        text=(
            "Run the experiment to plot Final Ciphertext "
            "Hamming Distance for each flipped bit."
        ),
        font=("Arial", 10),
        justify="left"
    )

    graph_info_label.pack(
        anchor="w",
        pady=(0, 8)
    )

    lab_figure = Figure(
        figsize=(9.5, 4.5),
        dpi=100
    )

    lab_axis = lab_figure.add_subplot(111)

    lab_axis.set_title(
        "AES-128 Avalanche Effect"
    )

    lab_axis.set_xlabel(
        "Flipped Bit Index"
    )

    lab_axis.set_ylabel(
        "Final Ciphertext Hamming Distance (bits)"
    )

    lab_axis.set_ylim(
        0,
        128
    )

    lab_axis.axhline(
        y=64,
        linestyle="--",
        linewidth=1.5,
        label="Ideal 50% Avalanche = 64 bits"
    )

    lab_axis.grid(
        True,
        alpha=0.25
    )

    lab_axis.legend()

    lab_figure.tight_layout()

    lab_graph_canvas = FigureCanvasTkAgg(
        lab_figure,
        master=graph_frame
    )

    lab_graph_canvas.draw()

    lab_graph_canvas.get_tk_widget().pack(
        fill="both",
        expand=True
    )

    # ========================================================
    # STATISTICS
    # ========================================================

    statistics_frame = tk.LabelFrame(
        content,
        text="Statistical Analysis",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=10
    )

    statistics_frame.pack(
        padx=25,
        pady=10,
        fill="x"
    )

    statistics_label = tk.Label(
        statistics_frame,
        text="Run the experiment to calculate statistics.",
        justify="left",
        font=("Courier", 11)
    )

    statistics_label.pack(
        anchor="w"
    )

    # ========================================================
    # RESULT
    # ========================================================

    result_frame = tk.LabelFrame(
        content,
        text="Result and Interpretation",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=10
    )

    result_frame.pack(
        padx=25,
        pady=(10, 25),
        fill="x"
    )

    result_label = tk.Label(
        result_frame,
        text="No experimental result available yet.",
        wraplength=1100,
        justify="left",
        font=("Arial", 10)
    )

    result_label.pack(
        anchor="w"
    )

    # ========================================================
    # UPDATE EXPERIMENT INFORMATION
    # ========================================================

    def update_experiment_information():

        experiment = experiment_var.get()

        if experiment == "plaintext":

            aim_label.configure(
                text=(
                    "To study the avalanche effect in AES-128 "
                    "by independently changing one bit of the "
                    "plaintext while keeping the encryption key "
                    "constant."
                )
            )

            objective_label.configure(
                text=(
                    "• Understand diffusion in AES-128.\n"
                    "• Measure ciphertext changes using Hamming distance.\n"
                    "• Calculate avalanche percentage for multiple trials.\n"
                    "• Compare the experimental mean with the 50% reference.\n"
                    "• Interpret variation across different flipped plaintext bits."
                )
            )

            theory_label.configure(
                text=(
                    "The avalanche effect describes the sensitivity of a "
                    "cryptographic algorithm to small input changes. In this "
                    "experiment, one plaintext bit is changed at a time while "
                    "the AES-128 key remains fixed. The resulting ciphertext "
                    "is compared with the original ciphertext using Hamming "
                    "distance. For a 128-bit ciphertext, a Hamming distance "
                    "near 64 bits corresponds to approximately 50% of the "
                    "ciphertext bits being different."
                )
            )

            procedure_label.configure(
                text=(
                    "1. Enter a 128-bit plaintext and AES-128 key.\n"
                    "2. Select the required range of plaintext bits.\n"
                    "3. Encrypt the original plaintext.\n"
                    "4. Flip one selected plaintext bit at a time.\n"
                    "5. Encrypt each modified plaintext using the same key.\n"
                    "6. Compare each ciphertext with the original ciphertext.\n"
                    "7. Record Hamming distance and avalanche percentage.\n"
                    "8. Calculate mean, minimum, maximum and standard deviation.\n"
                    "9. Interpret the experimental avalanche behaviour."
                )
            )

        else:

            aim_label.configure(
                text=(
                    "To study the avalanche effect in AES-128 "
                    "by independently changing one bit of the "
                    "encryption key while keeping the plaintext "
                    "constant."
                )
            )

            objective_label.configure(
                text=(
                    "• Study sensitivity of AES-128 to master-key changes.\n"
                    "• Relate key changes to the AES key expansion process.\n"
                    "• Measure ciphertext Hamming distance across multiple trials.\n"
                    "• Calculate mean avalanche percentage and variation.\n"
                    "• Compare observed behaviour with the 50% reference."
                )
            )

            theory_label.configure(
                text=(
                    "In the key avalanche experiment, the plaintext remains "
                    "unchanged while one bit of the 128-bit master key is "
                    "flipped independently in each trial. The changed master "
                    "key produces a different AES key schedule, affecting "
                    "the round keys and therefore the encryption process. "
                    "The resulting ciphertext is compared with the original "
                    "ciphertext using Hamming distance."
                )
            )

            procedure_label.configure(
                text=(
                    "1. Enter a 128-bit plaintext and AES-128 key.\n"
                    "2. Select the required range of key bits.\n"
                    "3. Encrypt the plaintext using the original key.\n"
                    "4. Flip one selected master-key bit at a time.\n"
                    "5. Encrypt the same plaintext using each modified key.\n"
                    "6. Compare each ciphertext with the original ciphertext.\n"
                    "7. Record Hamming distance and avalanche percentage.\n"
                    "8. Calculate mean, minimum, maximum and standard deviation.\n"
                    "9. Interpret the effect of master-key changes."
                )
            )

    # ========================================================
    # RANGE PARSER
    # ========================================================

    def get_bit_range():

        selected = range_var.get()

        ranges_map = {
            "0-7": (0, 7),
            "0-15": (0, 15),
            "0-31": (0, 31),
            "0-63": (0, 63),
            "0-127": (0, 127)
        }

        return ranges_map[selected]

    # ========================================================
    # CLEAR TABLE
    # ========================================================

    def clear_observation_table():

        for item in observation_tree.get_children():

            observation_tree.delete(
                item
            )

    # ========================================================
    # RUN EXPERIMENT
    # ========================================================
    def update_experiment_graph(data):

        observations = data.get(
            "observations",
            []
        )

        lab_axis.clear()

        # ----------------------------------------------------
        # BASIC AXIS CONFIGURATION
        # ----------------------------------------------------

        lab_axis.set_xlabel(
            "Flipped Bit Index"
        )

        lab_axis.set_ylabel(
            "Final Ciphertext Hamming Distance (bits)"
        )

        lab_axis.set_ylim(
            0,
            128
        )

        lab_axis.grid(
            True,
            alpha=0.25
        )

        # ----------------------------------------------------
        # IDEAL AVALANCHE REFERENCE
        # ----------------------------------------------------

        lab_axis.axhline(
            y=64,
            linestyle="--",
            linewidth=1.5,
            label="Ideal 50% Reference = 64 bits"
        )

        # ----------------------------------------------------
        # NO DATA
        # ----------------------------------------------------

        if not observations:

            lab_axis.set_title(
                "AES-128 Avalanche Experiment"
            )

            lab_axis.text(
                0.5,
                0.5,
                "No experiment data available.",
                horizontalalignment="center",
                verticalalignment="center",
                transform=lab_axis.transAxes
            )

            lab_axis.legend()

            lab_figure.tight_layout()
            lab_graph_canvas.draw()

            return

        # ----------------------------------------------------
        # EXTRACT OBSERVATIONS
        # ----------------------------------------------------

        bit_indices = [
            item["bit_index"]
            for item in observations
        ]

        hamming_distances = [
            item["final_hamming_distance"]
            for item in observations
        ]

        # ----------------------------------------------------
        # MEASURED VALUES
        # ----------------------------------------------------

        lab_axis.plot(
            bit_indices,
            hamming_distances,
            marker="o",
            markersize=4,
            linewidth=1.5,
            label="Measured Hamming Distance"
        )

        # ----------------------------------------------------
        # EXPERIMENTAL MEAN
        # ----------------------------------------------------

        statistics = data.get(
            "hamming_statistics",
            {}
        )

        mean_hd = statistics.get(
            "mean"
        )

        if mean_hd is not None:

            lab_axis.axhline(
                y=mean_hd,
                linestyle=":",
                linewidth=1.5,
                label=(
                    f"Experimental Mean = "
                    f"{mean_hd:.2f} bits"
                )
            )

        # ----------------------------------------------------
        # X-AXIS RANGE
        # ----------------------------------------------------

        if len(bit_indices) == 1:

            lab_axis.set_xlim(
                bit_indices[0] - 1,
                bit_indices[0] + 1
            )

        else:

            lab_axis.set_xlim(
                min(bit_indices),
                max(bit_indices)
            )

        # ----------------------------------------------------
        # TITLE BASED ON EXPERIMENT TYPE
        # ----------------------------------------------------

        experiment_type = data.get(
            "experiment_type",
            ""
        )

        if experiment_type == "plaintext":

            graph_title = (
                "AES-128 Plaintext Avalanche Experiment"
            )

        elif experiment_type == "key":

            graph_title = (
                "AES-128 Key Avalanche Experiment"
            )

        else:

            graph_title = (
                "AES-128 Avalanche Experiment"
            )

        lab_axis.set_title(
            graph_title
        )

        lab_axis.legend()

        lab_figure.tight_layout()

        lab_graph_canvas.draw()

    def export_experiment_csv():

        if not experiment_data:

            messagebox.showwarning(
                "No Experiment Data",
                "Run an AES-128 avalanche experiment before exporting results."
            )

            return

        observations = experiment_data.get(
            "observations",
            []
        )

        if not observations:

            messagebox.showwarning(
                "No Observation Data",
                "The current experiment does not contain observation data."
            )

            return

        experiment_type = experiment_data.get(
            "experiment_type",
            "unknown"
        )

        start_bit = experiment_data.get(
            "start_bit",
            0
        )

        end_bit = experiment_data.get(
            "end_bit",
            0
        )

        default_filename = (
            f"aes128_{experiment_type}_avalanche_"
            f"bits_{start_bit}_{end_bit}.csv"
        )

        file_path = filedialog.asksaveasfilename(
            title="Export AES-128 Experiment Results",
            defaultextension=".csv",
            initialfile=default_filename,
            filetypes=[
                ("CSV Files", "*.csv"),
                ("All Files", "*.*")
            ]
        )

        if not file_path:
            return

        try:

            with open(
                file_path,
                "w",
                newline="",
                encoding="utf-8"
            ) as csv_file:

                writer = csv.writer(
                    csv_file
                )

                # ============================================
                # REPORT HEADER
                # ============================================

                writer.writerow([
                    "AES-128 AVALANCHE EFFECT LABORATORY"
                ])

                writer.writerow([
                    "Interactive Cryptography Teaching and Analysis Laboratory"
                ])

                writer.writerow([])

                # ============================================
                # EXPERIMENT CONFIGURATION
                # ============================================

                writer.writerow([
                    "EXPERIMENT CONFIGURATION"
                ])

                writer.writerow([
                    "Experiment Type",
                    experiment_type
                ])

                writer.writerow([
                    "Start Bit",
                    start_bit
                ])

                writer.writerow([
                    "End Bit",
                    end_bit
                ])

                writer.writerow([
                    "Number of Trials",
                    len(observations)
                ])

                writer.writerow([
                    "Original Plaintext",
                    experiment_data.get(
                        "plaintext_hex",
                        ""
                    )
                ])

                writer.writerow([
                    "AES-128 Key",
                    experiment_data.get(
                        "key_hex",
                        ""
                    )
                ])

                writer.writerow([])

                # ============================================
                # HAMMING DISTANCE STATISTICS
                # ============================================

                hamming_stats = experiment_data.get(
                    "hamming_statistics",
                    {}
                )

                writer.writerow([
                    "HAMMING DISTANCE STATISTICS"
                ])

                writer.writerow([
                    "Count",
                    hamming_stats.get(
                        "count",
                        ""
                    )
                ])

                writer.writerow([
                    "Mean",
                    hamming_stats.get(
                        "mean",
                        ""
                    )
                ])

                writer.writerow([
                    "Minimum",
                    hamming_stats.get(
                        "minimum",
                        ""
                    )
                ])

                writer.writerow([
                    "Maximum",
                    hamming_stats.get(
                        "maximum",
                        ""
                    )
                ])

                writer.writerow([
                    "Population Standard Deviation",
                    hamming_stats.get(
                        "standard_deviation",
                        ""
                    )
                ])

                writer.writerow([])

                # ============================================
                # AVALANCHE PERCENTAGE STATISTICS
                # ============================================

                percentage_stats = experiment_data.get(
                    "avalanche_statistics",
                    {}
                )

                writer.writerow([
                    "AVALANCHE PERCENTAGE STATISTICS"
                ])

                writer.writerow([
                    "Count",
                    percentage_stats.get(
                        "count",
                        ""
                    )
                ])

                writer.writerow([
                    "Mean (%)",
                    percentage_stats.get(
                        "mean",
                        ""
                    )
                ])

                writer.writerow([
                    "Minimum (%)",
                    percentage_stats.get(
                        "minimum",
                        ""
                    )
                ])

                writer.writerow([
                    "Maximum (%)",
                    percentage_stats.get(
                        "maximum",
                        ""
                    )
                ])

                writer.writerow([
                    "Population Standard Deviation (%)",
                    percentage_stats.get(
                        "standard_deviation",
                        ""
                    )
                ])

                writer.writerow([])

                # ============================================
                # THEORETICAL REFERENCE
                # ============================================

                writer.writerow([
                    "THEORETICAL REFERENCE"
                ])

                writer.writerow([
                    "AES Block Size",
                    "128 bits"
                ])

                writer.writerow([
                    "Ideal Avalanche Percentage",
                    "50%"
                ])

                writer.writerow([
                    "Ideal Hamming Distance",
                    "64 bits"
                ])

                writer.writerow([
                    "Mean Distance From 50%",
                    experiment_data.get(
                        "mean_distance_from_50_percent",
                        ""
                    )
                ])

                writer.writerow([])

                # ============================================
                # OBSERVATION TABLE
                # ============================================

                writer.writerow([
                    "OBSERVATION TABLE"
                ])

                writer.writerow([
                    "Trial",
                    "Flipped Bit",
                    "Byte Index",
                    "Bit in Byte from MSB",
                    "Final Hamming Distance",
                    "Avalanche Percentage",
                    "Modified Plaintext",
                    "Modified Key",
                    "Modified Ciphertext"
                ])

                for observation in observations:

                    writer.writerow([
                        observation.get(
                            "trial",
                            ""
                        ),
                        observation.get(
                            "bit_index",
                            ""
                        ),
                        observation.get(
                            "byte_index",
                            ""
                        ),
                        observation.get(
                            "bit_in_byte_from_msb",
                            ""
                        ),
                        observation.get(
                            "final_hamming_distance",
                            ""
                        ),
                        observation.get(
                            "final_avalanche_percentage",
                            ""
                        ),
                        observation.get(
                            "modified_plaintext_hex",
                            ""
                        ),
                        observation.get(
                            "modified_key_hex",
                            ""
                        ),
                        observation.get(
                            "modified_ciphertext_hex",
                            ""
                        )
                    ])

                writer.writerow([])

                # ============================================
                # RESULT / INTERPRETATION
                # ============================================

                writer.writerow([
                    "RESULT AND INTERPRETATION"
                ])

                writer.writerow([
                    experiment_data.get(
                        "interpretation",
                        ""
                    )
                ])

            messagebox.showinfo(
                "CSV Export Complete",
                "AES-128 experiment results were exported successfully."
            )

        except Exception as error:

            messagebox.showerror(
                "CSV Export Error",
                str(error)
            )

    def generate_lab_report():

        if not experiment_data:
            messagebox.showwarning(
                "No Experiment Data",
                "Run an AES-128 avalanche experiment before generating the lab report."
            )
            return

        observations = experiment_data.get("observations", [])

        if not observations:
            messagebox.showwarning(
                "No Observation Data",
                "The current experiment does not contain observation data."
            )
            return

        experiment_type = experiment_data.get(
            "experiment_type",
            "unknown"
        )

        start_bit = experiment_data.get("start_bit", 0)
        end_bit = experiment_data.get("end_bit", 0)

        plaintext_hex = experiment_data.get(
            "plaintext_hex",
            ""
        )

        key_hex = experiment_data.get(
            "key_hex",
            ""
        )

        hamming_stats = experiment_data.get(
            "hamming_statistics",
            {}
        )

        percentage_stats = experiment_data.get(
            "percentage_statistics",
            {}
        )

        interpretation = experiment_data.get(
            "interpretation",
            ""
        )

        # --------------------------------------------
        # Experiment-specific wording
        # --------------------------------------------

        if experiment_type == "plaintext":

            experiment_title = (
                "Study of the Avalanche Effect in AES-128 "
                "by Changing Plaintext Bits"
            )

            aim_text = (
                "To study and analyze the avalanche effect in AES-128 "
                "encryption by changing one bit of the plaintext at a time "
                "while keeping the 128-bit encryption key constant."
            )

            variable_text = (
                "Independent Variable : Plaintext bit position\n"
                "Controlled Variable  : AES-128 encryption key\n"
                "Measured Variable    : Hamming distance between ciphertexts"
            )

        else:

            experiment_title = (
                "Study of the Avalanche Effect in AES-128 "
                "by Changing Key Bits"
            )

            aim_text = (
                "To study and analyze the avalanche effect in AES-128 "
                "encryption by changing one bit of the 128-bit key at a time "
                "while keeping the plaintext constant."
            )

            variable_text = (
                "Independent Variable : AES-128 key bit position\n"
                "Controlled Variable  : Plaintext block\n"
                "Measured Variable    : Hamming distance between ciphertexts"
            )

        # --------------------------------------------
        # Build observation table
        # --------------------------------------------

        observation_lines = []

        header = (
            f"{'Trial':<8}"
            f"{'Bit':<8}"
            f"{'Byte':<8}"
            f"{'Bit/MSB':<12}"
            f"{'HD/128':<12}"
            f"{'Avalanche %':<15}"
        )

        observation_lines.append(header)
        observation_lines.append("-" * 63)

        for observation in observations:

            observation_lines.append(
                f"{str(observation.get('trial', '')):<8}"
                f"{str(observation.get('bit_index', '')):<8}"
                f"{str(observation.get('byte_index', '')):<8}"
                f"{str(observation.get('bit_in_byte_from_msb', '')):<12}"
                f"{str(observation.get('final_hamming_distance', '')):<12}"
                f"{str(observation.get('final_avalanche_percentage', '')):<15}"
            )

        observation_table = "\n".join(
            observation_lines
        )

        # --------------------------------------------
        # Statistics
        # --------------------------------------------

        hd_mean = hamming_stats.get("mean", "")
        hd_min = hamming_stats.get("minimum", "")
        hd_max = hamming_stats.get("maximum", "")
        hd_std = hamming_stats.get(
            "standard_deviation",
            ""
        )

        percentage_mean = percentage_stats.get(
            "mean",
            ""
        )

        # If the percentage statistics field is not
        # available, calculate percentage from HD mean.
        if percentage_mean == "" and hd_mean != "":
            try:
                percentage_mean = round(
                    (float(hd_mean) / 128.0) * 100.0,
                    4
                )
            except (ValueError, TypeError):
                percentage_mean = ""

        # --------------------------------------------
        # Formal report
        # --------------------------------------------

        report_text = f"""
AES-128 CRYPTOGRAPHY LABORATORY
FORMAL STUDENT LABORATORY RECORD
================================================================

EXPERIMENT TITLE
----------------------------------------------------------------
{experiment_title}


1. AIM
----------------------------------------------------------------
{aim_text}


2. LEARNING OBJECTIVES
----------------------------------------------------------------
After completing this experiment, the student should be able to:

1. Explain the avalanche effect in a symmetric block cipher.
2. Describe the role of diffusion in AES-128.
3. Perform controlled single-bit modifications to AES input data.
4. Compare original and modified AES-128 ciphertexts.
5. Calculate Hamming distance between two 128-bit ciphertexts.
6. Express the avalanche effect as a percentage.
7. Interpret experimental AES diffusion using statistical measures.


3. THEORY
----------------------------------------------------------------
AES (Advanced Encryption Standard) is a symmetric-key block cipher.

AES-128 operates on:

Block Size : 128 bits
Key Size   : 128 bits
Rounds     : 10
State Size : 4 x 4 bytes

The principal AES round transformations are:

1. SubBytes
2. ShiftRows
3. MixColumns
4. AddRoundKey

The final AES round does not perform MixColumns.

An important cryptographic property is the avalanche effect. A small
change in the input, ideally a single-bit change, should cause a large
and apparently unpredictable change in the ciphertext.

For a 128-bit ciphertext, an ideal avalanche response is approximately
50 percent of the output bits changing.

Therefore:

Ideal Hamming Distance = 128 / 2 = 64 bits

and:

Avalanche Percentage = (Hamming Distance / 128) x 100


4. EXPERIMENTAL VARIABLES
----------------------------------------------------------------
{variable_text}


5. EXPERIMENT CONFIGURATION
----------------------------------------------------------------
AES Variant       : AES-128
AES Block Size    : 128 bits
AES Key Size      : 128 bits
Number of Rounds  : 10

Experiment Type   : {experiment_type}
Start Bit         : {start_bit}
End Bit           : {end_bit}
Number of Trials  : {len(observations)}

Original Plaintext:
{plaintext_hex}

Original AES-128 Key:
{key_hex}


6. PROCEDURE
----------------------------------------------------------------
1. Enter a 128-bit plaintext block.

2. Enter a 128-bit AES encryption key.

3. Encrypt the original plaintext using AES-128.

4. Select the required avalanche experiment.

5. Select the range of bit positions to be tested.

6. Flip exactly one selected bit for each experimental trial.

7. Keep all other experimental parameters unchanged.

8. Encrypt the modified input using AES-128.

9. Compare the modified ciphertext with the original ciphertext.

10. Calculate the Hamming distance between the two 128-bit
    ciphertexts.

11. Calculate the avalanche percentage using:

       Avalanche Percentage =
       (Hamming Distance / 128) x 100

12. Repeat the experiment for all selected bit positions.

13. Record the observations.

14. Calculate the mean, minimum, maximum and standard deviation.

15. Compare the experimental mean with the ideal AES avalanche
    reference of 64 changed bits or 50 percent.


7. OBSERVATION TABLE
----------------------------------------------------------------
{observation_table}


8. STATISTICAL ANALYSIS
----------------------------------------------------------------
Number of Observations       : {len(observations)}

Mean Hamming Distance        : {hd_mean} bits
Minimum Hamming Distance     : {hd_min} bits
Maximum Hamming Distance     : {hd_max} bits
Population Standard Deviation: {hd_std}

Mean Avalanche Percentage    : {percentage_mean} %

Ideal Hamming Distance       : 64 bits
Ideal Avalanche Percentage   : 50 %


9. RESULT AND INTERPRETATION
----------------------------------------------------------------
{interpretation}


10. CONCLUSION
----------------------------------------------------------------
The AES-128 avalanche effect was experimentally studied by performing
controlled single-bit modifications and comparing the resulting
ciphertexts.

The observed Hamming distances demonstrate how changes introduced at
the input propagate through the AES transformations and affect the
128-bit ciphertext.

For an ideal avalanche response, approximately 64 of the 128 output
bits are expected to change. The experimental mean can therefore be
compared with 64 bits, or 50 percent, to evaluate the diffusion
demonstrated by AES-128.


11. FORMULAE USED
----------------------------------------------------------------
Hamming Distance:

HD(C1, C2) = Number of differing bit positions between C1 and C2

Avalanche Percentage:

Avalanche Percentage = (HD / 128) x 100

Ideal AES-128 Avalanche:

HD = 64 bits

Avalanche Percentage = 50 %


================================================================
AES-128 Interactive Cryptography Teaching and Analysis Laboratory
================================================================
""".strip()

        # --------------------------------------------
        # Report preview window
        # --------------------------------------------

        report_window = tk.Toplevel(
            lab
        )

        report_window.title(
            "AES-128 Formal Student Lab Record"
        )

        report_window.geometry(
            "950x800"
        )

        report_window.minsize(
            800,
            650
        )

        title_label = tk.Label(
            report_window,
            text="AES-128 FORMAL STUDENT LAB RECORD",
            font=("Arial", 16, "bold")
        )

        title_label.pack(
            pady=(12, 5)
        )

        report_box = scrolledtext.ScrolledText(
            report_window,
            wrap=tk.WORD,
            font=("Courier", 11)
        )

        report_box.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=8
        )

        report_box.insert(
            tk.END,
            report_text
        )

        # Students can review/edit the report before saving.

        # --------------------------------------------
        # Save report
        # --------------------------------------------

        def save_lab_report():

            default_filename = (
                f"aes128_{experiment_type}_"
                f"avalanche_lab_report_"
                f"bits_{start_bit}_{end_bit}.txt"
            )

            file_path = filedialog.asksaveasfilename(
                title="Save AES-128 Lab Report",
                defaultextension=".txt",
                initialfile=default_filename,
                filetypes=[
                    ("Text Files", "*.txt"),
                    ("All Files", "*.*")
                ]
            )

            if not file_path:
                return

            try:

                current_report = report_box.get(
                    "1.0",
                    tk.END
                ).rstrip()

                with open(
                    file_path,
                    "w",
                    encoding="utf-8"
                ) as report_file:

                    report_file.write(
                        current_report
                    )

                messagebox.showinfo(
                    "Report Saved",
                    "AES-128 formal student lab report was saved successfully."
                )

            except Exception as error:

                messagebox.showerror(
                    "Report Save Error",
                    str(error)
                )

        button_frame = tk.Frame(
            report_window
        )

        button_frame.pack(
            pady=(0, 12)
        )

        save_button = tk.Button(
            button_frame,
            text="SAVE REPORT",
            command=save_lab_report,
            width=18,
            font=("Arial", 10, "bold")
        )

        save_button.grid(
            row=0,
            column=0,
            padx=5
        )

        close_button = tk.Button(
            button_frame,
            text="CLOSE",
            command=report_window.destroy,
            width=12
        )

        close_button.grid(
            row=0,
            column=1,
            padx=5
        )


    def run_lab_experiment():

        plaintext_hex = (
            plaintext_entry
            .get()
            .replace(" ", "")
            .strip()
        )

        key_hex = (
            key_entry
            .get()
            .replace(" ", "")
            .strip()
        )

        if len(plaintext_hex) != 32:

            messagebox.showerror(
                "Invalid Plaintext",
                (
                    "Plaintext must contain exactly "
                    "32 hexadecimal characters."
                )
            )

            return

        if len(key_hex) != 32:

            messagebox.showerror(
                "Invalid AES-128 Key",
                (
                    "Key must contain exactly "
                    "32 hexadecimal characters."
                )
            )

            return

        try:

            bytes.fromhex(
                plaintext_hex
            )

            bytes.fromhex(
                key_hex
            )

        except ValueError:

            messagebox.showerror(
                "Invalid Hexadecimal Input",
                (
                    "Plaintext and key must contain "
                    "hexadecimal characters only."
                )
            )

            return

        start_bit, end_bit = (
            get_bit_range()
        )

        run_button.configure(
            state="disabled",
            text="RUNNING..."
        )

        lab.update_idletasks()

        try:

            response = requests.post(
                "http://localhost:8000/aes/lab/avalanche",
                json={
                    "plaintext_hex":
                        plaintext_hex,
                    "key_hex":
                        key_hex,
                    "experiment_type":
                        experiment_var.get(),
                    "start_bit":
                        start_bit,
                    "end_bit":
                        end_bit
                },
                timeout=60
            )

            response.raise_for_status()

            data = response.json()

        except Exception as e:

            messagebox.showerror(
                "Experiment Error",
                str(e)
            )

            run_button.configure(
                state="normal",
                text="RUN LAB EXPERIMENT"
            )

            return

        run_button.configure(
            state="normal",
            text="RUN LAB EXPERIMENT"
        )

        experiment_data.clear()

        experiment_data.update(data)

        update_experiment_graph(
            data
        )

        # ----------------------------------------------------
        # OBSERVATION TABLE
        # ----------------------------------------------------

        clear_observation_table()

        for observation in (
            experiment_data[
                "observations"
            ]
        ):

            observation_tree.insert(
                "",
                "end",
                values=(
                    observation["trial"],
                    observation["bit_index"],
                    observation["byte_index"],
                    observation[
                        "bit_in_byte_from_msb"
                    ],
                    (
                        f"{observation['final_hamming_distance']}"
                        "/128"
                    ),
                    (
                        f"{observation['final_avalanche_percentage']:.2f}%"
                    )
                )
            )

        # ----------------------------------------------------
        # STATISTICS
        # ----------------------------------------------------

        hd_stats = experiment_data[
            "hamming_statistics"
        ]

        av_stats = experiment_data[
            "avalanche_statistics"
        ]

        statistics_text = (
            f"Number of trials              : "
            f"{experiment_data['total_trials']}\n\n"

            f"HAMMING DISTANCE\n"
            f"Mean                          : "
            f"{hd_stats['mean']:.4f} bits\n"
            f"Minimum                       : "
            f"{hd_stats['minimum']} bits\n"
            f"Maximum                       : "
            f"{hd_stats['maximum']} bits\n"
            f"Population standard deviation : "
            f"{hd_stats['standard_deviation']:.4f} bits\n\n"

            f"AVALANCHE PERCENTAGE\n"
            f"Mean                          : "
            f"{av_stats['mean']:.4f}%\n"
            f"Minimum                       : "
            f"{av_stats['minimum']:.2f}%\n"
            f"Maximum                       : "
            f"{av_stats['maximum']:.2f}%\n"
            f"Population standard deviation : "
            f"{av_stats['standard_deviation']:.4f}%\n\n"

            f"Reference                     : "
            f"50.00% / 64 bits\n"
            f"Mean distance from 50%        : "
            f"{experiment_data['mean_distance_from_50_percent']:.4f}%"
        )

        statistics_label.configure(
            text=statistics_text
        )

        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        experiment_name = (
            "plaintext"
            if experiment_data[
                "experiment_type"
            ] == "plaintext"
            else "AES-128 master key"
        )

        result_text = (
            f"The experiment independently changed "
            f"{experiment_data['total_trials']} bit(s) of the "
            f"{experiment_name}. The mean final ciphertext "
            f"Hamming distance was "
            f"{hd_stats['mean']:.4f} bits out of 128, "
            f"corresponding to a mean avalanche percentage "
            f"of {av_stats['mean']:.4f}%.\n\n"

            f"{experiment_data['interpretation']}\n\n"

            f"The 50% value is used as a statistical reference "
            f"for strong diffusion; an individual trial is not "
            f"expected to produce exactly 64 changed bits."
        )

        result_label.configure(
            text=result_text
        )

        messagebox.showinfo(
            "Experiment Complete",
            (
                f"{experiment_data['total_trials']} "
                "AES-128 avalanche trials completed."
            )
        )

    # ========================================================
    # RUN BUTTON
    # ========================================================

    run_button = tk.Button(
        config_frame,
        text="RUN LAB EXPERIMENT",
        command=run_lab_experiment,
        width=25,
        font=("Arial", 10, "bold")
    )

    run_button.grid(
        row=8,
        column=0,
        columnspan=5,
        pady=(12, 3)
    )

    export_csv_button = tk.Button(
        config_frame,
        text="EXPORT RESULTS TO CSV",
        command=export_experiment_csv,
        width=25,
        font=("Arial", 10, "bold")
    )

    export_csv_button.grid(
        row=9,
        column=0,
        columnspan=5,
        pady=(3, 8)
    )

    report_button = tk.Button(
        config_frame,
        text="GENERATE LAB REPORT",
        command=generate_lab_report,
        width=25,
        font=("Arial", 10, "bold")
    )

    report_button.grid(
        row=10,
        column=0,
        columnspan=5,
        pady=(3, 8)
    )
    # Initial content
    update_experiment_information()


def coming_soon(module_name, phase):

    messagebox.showinfo(
        module_name,
        (
            f"{module_name}\n\n"
            f"This AES-128 laboratory module "
            f"will be implemented in {phase}."
        )
    )


def open_theory():

    theory_window = tk.Toplevel(root)

    theory_window.title(
        "AES-128 Theory and Reference"
    )

    theory_window.geometry(
        "800x650"
    )

    tk.Label(
        theory_window,
        text="AES-128 Theory & Reference",
        font=("Arial", 20, "bold")
    ).pack(
        pady=15
    )

    theory_text = """
AES — ADVANCED ENCRYPTION STANDARD
==================================

AES-128 is a symmetric-key block cipher.


CORE PARAMETERS
---------------

Block Size:
128 bits = 16 bytes

Key Size:
128 bits = 16 bytes

Number of Rounds:
10

State:
4 × 4 byte matrix

Round Keys:
11

Expanded Key:
44 words (W0 through W43)


AES-128 ENCRYPTION
==================

INPUT
  |
  v

Initial AddRoundKey
  |
  v

Rounds 1 through 9:

SubBytes
  |
ShiftRows
  |
MixColumns
  |
AddRoundKey

  |
  v

Round 10:

SubBytes
  |
ShiftRows
  |
AddRoundKey

  |
  v

CIPHERTEXT


IMPORTANT
=========

The final AES round does NOT contain MixColumns.


SUBBYTES
========

Each byte of the AES state is replaced using
the AES substitution box (S-box).

Purpose:
Introduce non-linearity into AES.


SHIFTROWS
=========

Rows of the AES state are cyclically shifted.

Row 0 -> shift by 0
Row 1 -> shift by 1
Row 2 -> shift by 2
Row 3 -> shift by 3

This helps distribute bytes across columns.


MIXCOLUMNS
==========

Each column is transformed using arithmetic
in the finite field GF(2^8).

Purpose:
Diffusion.


ADDROUNDKEY
===========

The AES state is XORed with the round key.

State XOR Round Key = New State

This directly incorporates key material
into the AES state.


AES-128 KEY EXPANSION
=====================

The original 128-bit key contains four
32-bit words:

W0 W1 W2 W3

AES expands these into:

W0 through W43

These 44 words form eleven round keys:

Round Key 0
Round Key 1
...
Round Key 10


AES-128 SECURITY STRUCTURE
==========================

SubBytes:
Non-linearity / confusion

ShiftRows:
Byte permutation

MixColumns:
Diffusion

AddRoundKey:
Key mixing
"""

    theory_box = scrolledtext.ScrolledText(
        theory_window,
        wrap=tk.WORD,
        font=("Courier", 11)
    )

    theory_box.pack(
        padx=20,
        pady=(0, 20),
        fill="both",
        expand=True
    )

    theory_box.insert(
        tk.END,
        theory_text
    )

    theory_box.config(
        state="disabled"
    )


def create_dashboard_card(
    parent,
    row,
    column,
    title,
    description,
    command,
    status
):

    card = tk.LabelFrame(
        parent,
        text=title,
        font=("Arial", 13, "bold"),
        padx=15,
        pady=12,
        width=360,
        height=145
    )

    card.grid(
        row=row,
        column=column,
        padx=12,
        pady=12,
        sticky="nsew"
    )

    card.grid_propagate(
        False
    )

    tk.Label(
        card,
        text=description,
        font=("Arial", 10),
        justify="left",
        wraplength=320
    ).pack(
        anchor="w"
    )

    tk.Button(
        card,
        text="OPEN",
        command=command,
        width=14,
        font=("Arial", 10, "bold")
    ).pack(
        pady=(10, 3)
    )

    tk.Label(
        card,
        text=status,
        font=("Arial", 9)
    ).pack()

# ------------------------------------------------
# MAIN WINDOW
# ------------------------------------------------

# ============================================================
# AES-128 LABORATORY DASHBOARD
# ============================================================

root = tk.Tk()

root.title(
    "AES-128 Cryptography Laboratory"
)

root.geometry(
    "900x760"
)

root.minsize(
    850,
    700
)


# ============================================================
# HEADER
# ============================================================

tk.Label(
    root,
    text="AES-128 CRYPTOGRAPHY LAB",
    font=("Arial", 24, "bold")
).pack(
    pady=(18, 3)
)


tk.Label(
    root,
    text="Interactive Dockerized Teaching & Analysis Tool",
    font=("Arial", 12)
).pack()


tk.Label(
    root,
    text=(
        "Block: 128 bits    "
        "Key: 128 bits    "
        "Rounds: 10    "
        "State: 4 x 4 bytes"
    ),
    font=("Courier", 11, "bold")
).pack(
    pady=10
)


separator = tk.Frame(
    root,
    height=2,
    bd=1,
    relief="sunken"
)

separator.pack(
    fill="x",
    padx=30,
    pady=(3, 8)
)


# ============================================================
# DASHBOARD
# ============================================================

dashboard = tk.Frame(
    root
)

dashboard.pack(
    padx=20,
    pady=5,
    fill="both",
    expand=True
)


dashboard.grid_columnconfigure(
    0,
    weight=1
)

dashboard.grid_columnconfigure(
    1,
    weight=1
)


# ============================================================
# CARD 1 — STEP VISUALIZER
# ============================================================

create_dashboard_card(
    dashboard,
    0,
    0,
    "Step-by-Step Visualizer",
    (
        "Explore all 41 internal AES-128 "
        "encryption states across ten rounds."
    ),
    open_aes_visualizer,
    "AVAILABLE"
)


# ============================================================
# CARD 2 — TRANSFORMATION LAB
# ============================================================

create_dashboard_card(
    dashboard,
    0,
    1,
    "Transformation Laboratory",
    (
        "Explore SubBytes, ShiftRows, "
        "MixColumns and AddRoundKey through "
        "dedicated interactive laboratories."
    ),
    open_transformation_hub,
    "AVAILABLE"
)

# ============================================================
# CARD 3 — KEY EXPANSION
# ============================================================

create_dashboard_card(
    dashboard,
    1,
    0,
    "Key Expansion Laboratory",
    (
        "Explore W0–W43, RotWord, SubWord, "
        "Rcon, XOR derivations and all "
        "11 AES-128 round keys."
    ),
    open_key_expansion_lab,
    "AVAILABLE"
)

# ============================================================
# CARD 4 — AVALANCHE
# ============================================================

create_dashboard_card(
    dashboard,
    1,
    1,
    "Avalanche Laboratory",
    (
        "Flip one plaintext or key bit and "
        "measure AES-128 diffusion using "
        "Hamming distance across all 41 states."
    ),
    open_avalanche_lab,
    "AVAILABLE"
)

# ============================================================
# CARD 5 — THEORY
# ============================================================

create_dashboard_card(
    dashboard,
    2,
    0,
    "AES-128 Theory",
    (
        "Built-in reference covering AES structure, "
        "rounds, transformations and key expansion."
    ),
    open_theory,
    "AVAILABLE"
)


# ============================================================
# CARD 6 — LAB EXPERIMENT MODE
# ============================================================

create_dashboard_card(
    dashboard,
    2,
    1,
    "Lab Experiment Mode",
    (
        "Conduct formal AES-128 plaintext and key "
        "avalanche experiments with observation "
        "tables and statistical analysis."
    ),
    open_lab_experiment_mode,
    "AVAILABLE"
)

# ============================================================
# FOOTER
# ============================================================

tk.Label(
    root,
    text=(
        "AES-128 Educational Simulator  |  "
        "FastAPI Cryptographic Backend in Docker"
    ),
    font=("Arial", 9)
).pack(
    pady=(3, 12)
)

root.mainloop()