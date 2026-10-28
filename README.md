# AES-128 Cryptography Laboratory

An interactive Dockerized teaching, visualization, and analysis platform for
AES-128 cryptography.

The application combines a Python Tkinter graphical interface with a
Dockerized FastAPI backend to provide detailed visualization of AES-128
internal operations, key expansion, avalanche analysis, and structured
student laboratory experiments.

---

## Features

### AES-128 Step-by-Step Visualizer
- Visualizes the complete AES-128 encryption process.
- Displays 41 internal AES states.
- Shows the current round and transformation.
- Displays the corresponding round key.
- Supports Previous, Next, and slider-based navigation.

### Transformation Laboratory

Interactive visualization of the four AES transformations:

- SubBytes and AES S-Box
- ShiftRows
- MixColumns and GF(2^8) arithmetic
- AddRoundKey and XOR

The laboratory displays before/after state matrices and detailed
transformation calculations.

### Key Expansion Laboratory

- Visualizes AES-128 key scheduling.
- Displays words W0 through W43.
- Demonstrates RotWord, SubWord, Rcon, and XOR operations.
- Displays all 11 AES round keys.

### Avalanche Analysis Laboratory

Supports:

- Plaintext bit-flip experiments
- Key bit-flip experiments
- 128 selectable bit positions
- Hamming-distance calculation
- Avalanche percentage calculation
- Comparison of original and modified AES states
- 41-state avalanche propagation graph

### Student Laboratory Experiment Mode

Provides a structured environment for performing AES avalanche experiments.

Features include:

- Configurable plaintext and key
- Plaintext or key avalanche experiments
- Selectable bit ranges
- Multi-trial execution
- Observation tables
- Statistical analysis
- Experimental graphs
- CSV result export
- Formal laboratory report generation

---

## System Architecture

The application follows a client-server architecture:

```text
User
  |
  v
Tkinter Desktop GUI
  |
  | HTTP / JSON
  v
FastAPI REST API
(Docker Container)
  |
  v
AES-128 Teaching and Analysis Engine
  |
  v
JSON Results
  |
  v
Interactive Visualization / Analysis

The graphical interface runs on the host computer while the cryptographic
backend executes inside a Docker container.
Technology Stack
Component	Technology
Programming Language	Python
Desktop GUI	Tkinter
Backend API	FastAPI
Containerization	Docker
AES-GCM Utility	Python cryptography library
AES Teaching Engine	Pure Python AES-128 implementation
Graphing	Matplotlib
Communication	HTTP / REST / JSON


Project Structure
crypto-gui-docker/
|
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py
│   └── aes_teaching.py
|
├── gui/
│   └── crypto_gui.py
|
├── docs/
│   ├── AES128_Cryptography_Lab_Technical_Report.pdf
│   └── screenshots/
│       ├── dashboard.png
│       ├── step_visualizer.png
│       ├── transformation_lab.png
│       ├── key_expansion.png
│       ├── avalanche_analysis.png
│       └── student_lab_experiment.png
|
├── .gitignore
└── README.md

Application Dashboard

The dashboard provides access to the major teaching and analysis modules.
Step-by-Step AES Visualization

The AES teaching engine records 41 internal states during AES-128 encryption.

The recorded sequence consists of:
- Input state
- Initial AddRoundKey
- Rounds 1-9:
  - SubBytes
  - ShiftRows
  - MixColumns
  - AddRoundKey
- Round 10:
  - SubBytes
  - ShiftRows
  - AddRoundKey
Transformation Laboratory

Each AES transformation can be investigated independently using actual
intermediate states produced by the AES engine.
Key Expansion Laboratory

The key expansion laboratory exposes all 44 AES key-schedule words
(W0-W43) and the 11 resulting round keys.
Avalanche Analysis

A selected plaintext or key bit can be flipped and the modified encryption
compared with the original encryption.

For corresponding AES states, the system calculates:
Hamming Distance = Number of differing bits

Avalanche Percentage =
(Hamming Distance / 128) x 100

The resulting graph demonstrates how a one-bit modification propagates
through the AES rounds.
Student Laboratory Experiment

The experiment module automates repeated bit-flip trials and produces
observation tables, statistics, graphs, CSV results, and formal laboratory
records.
AES-128 Validation
The implementation was validated using the standard AES-128 known-answer
test vector.
Plaintext:
00112233445566778899AABBCCDDEEFF

Key:
000102030405060708090A0B0C0D0E0F

Expected Ciphertext:
69C4E0D86A7B0430D8CDB78070B4C55A

The teaching engine produces:
69C4E0D86A7B0430D8CDB78070B4C55A

confirming correct AES-128 encryption for the reference vector.
Running the Project
1. Start the Docker Backend
From the project directory:
cd backend
docker build -t crypto-api .
docker run --rm -p 8000:8000 --name crypto-api-container crypto-api

The API will be available at:
http://localhost:8000

2. Install GUI Dependencies
Create and activate a Python virtual environment if required.
cd gui

python3 -m venv venv
source venv/bin/activate

Install the required GUI-side packages:
pip install requests matplotlib

3. Start the GUI
python crypto_gui.py

Main API Endpoints
The FastAPI backend provides endpoints for operations including:
AES encryption/decryption
AES step visualization
AES key expansion
Single-bit avalanche analysis
Multi-trial avalanche experiments

See the technical report for a detailed description of the implementation
logic and experimental workflow.
Technical Report
The complete project technical report is available here:

[Technical Report](docs/AES128_Cryptography_Lab_Technical_Report.pdf)
Project Scope
This project focuses specifically on AES-128 as an educational
cryptography laboratory.

The raw AES teaching implementation is used for visualization and analysis,
while authenticated AES-GCM functionality is maintained separately for
practical encryption/decryption operations.
Educational Purpose
The software is intended as a teaching and experimentation platform for
students studying cryptography and information security.

It enables students to observe internal cryptographic transformations that
are normally hidden inside conventional cryptographic libraries.
License
This project is intended for academic and educational use.

