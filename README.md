# Secure Image Steganography & Steganalysis Suite

This project is a Java-based steganography toolkit that lets you hide a secret message inside an image, recover it later, check whether an image contains hidden data, and compare different steganographic techniques.

It combines:

- LSB (Least Significant Bit) embedding and extraction
- PVD (Pixel Value Differencing) steganography
- AES-256-GCM authenticated encryption
- PBKDF2 password-based key derivation
- Steganalysis checks for hidden payloads
- Benchmarking and CSV export for algorithm comparison

The application is designed as a command-line research tool and is best suited for PNG images where the least significant bits can be preserved safely.

---

## Why this project is useful

You can use it to:

- hide a secret message inside a cover image
- recover the message securely with the same password
- detect suspicious images using steganalysis
- compare LSB and PVD under different payload sizes
- export evaluation data for analysis in spreadsheets or reports

---

## Key features

### Secure embedding

- Encrypts plaintext using AES-256-GCM
- Derives the key with PBKDF2WithHmacSHA256
- Generates a random salt and IV for every message
- Embeds the encrypted payload into image pixels
- Saves the result as a PNG to avoid lossy compression issues

### Secure extraction

- Reads the hidden payload from the stego image
- Verifies the AES-GCM authentication tag
- Rejects tampered payloads or incorrect passwords with a security warning

### Steganalysis

- LSB statistical analysis
- Chi-square analysis
- RS analysis
- DCT-based analysis
- Suspicion scoring and formatted reports

### Experimental evaluation

- Compares LSB vs PVD at 1%, 5%, 10%, and 20% payload sizes
- Reports PSNR, SSIM, extraction success, and suspicion score
- Writes results to `evaluation_results.csv`

---

## Project structure

```text
Image-Steganography-using-LSB/
├── src/
│   ├── Main.java
│   ├── EmbedLSB.java
│   ├── ExtractLSB.java
│   ├── TextEncryptor.java
│   ├── TextDecryptor.java
│   ├── Steganalyzer.java
│   ├── SteganalysisReport.java
│   ├── LsbAnalysis.java
│   ├── ChiSquareAnalysis.java
│   ├── RSAnalysis.java
│   ├── DctAnalysis.java
│   ├── PvdSteganography.java
│   ├── ExperimentRunner.java
│   ├── ExperimentResult.java
│   ├── ImageQualityMetrics.java
│   └── Pixel.java
├── pictures/
│   └── input/
│       └── cute_dog.png
├── README.md
├── evaluation_results.csv
├── lib/
├── .idea/
└── .iml file
```

---

## Requirements

- Java 17 or newer
- A PNG image for embedding
- A password that you will use for both encryption and decryption

---

## How it works

### 1. Encryption and key derivation
The project uses:

- PBKDF2WithHmacSHA256 for password-based key derivation
- a 16-byte random salt
- a 12-byte random IV
- AES-256-GCM for authenticated encryption
- a GMAC authentication tag to detect tampering

### 2. Embedding the payload
The encrypted payload is converted into binary and embedded into the least significant bits of image pixels. The LSB implementation uses a 3-pixel-per-character design for the hidden message payload.

### 3. Extraction and verification
When extracting, the program reads the hidden bits back from the image, validates the payload, and decrypts the original message with the same password.

### 4. Steganalysis
The analysis tools inspect the image for signs of hidden content using LSB statistics, Chi-square testing, RS analysis, and DCT-based forensic checks.

---

## Quick start

### Compile the project

Windows PowerShell:

```powershell
javac -d out $(Get-ChildItem -Path src -Filter *.java | Select-Object -ExpandProperty FullName)
```

macOS/Linux:

```bash
javac -d out src/*.java
```

### Run the app

```bash
java -cp out Main
```

---

## Menu options

When the app starts, it shows four choices:

- A: Encrypt and embed a secret message into an image
- B: Extract, authenticate, and decrypt a message from an image
- C: Run steganalysis on an image
- D: Run experiments and compare algorithms

### Option A: Embed a message

The program asks for:

1. the message to hide
2. the password
3. the source image path
4. the output stego-image path

Example input:

```text
A
Hello hidden world!
secret123
pictures/input/cute_dog.png
pictures/out/stego.png
```

### Option B: Extract and decrypt a message

The program asks for:

1. the stego image path
2. the decryption password

Example input:

```text
B
pictures/out/stego.png
secret123
```

If the image was modified or the password is wrong, the application reports a security alert rather than returning plaintext.

### Option C: Run steganalysis

Provide the image path you want to inspect. The tool analyzes the image using LSB, Chi-square, RS, and DCT methods and prints a structured forensic report.

### Option D: Run benchmark experiments

Provide:

- the cover image path
- the CSV output path

The runner compares LSB and PVD at 1%, 5%, 10%, and 20% payload sizes and exports the results to CSV.

---

## Example workflow

Run the app:

```bash
java -cp out Main
```

Then choose:

```text
A
Hello hidden world!
secret123
pictures/input/cute_dog.png
pictures/out/stego.png
```

To recover the message later:

```text
B
pictures/out/stego.png
secret123
```

---

## Important usage notes

- Use a lossless image format such as PNG for embedding.
- Keep the same password for both embedding and extraction.
- Do not edit the stego image after embedding, or the integrity check will fail.
- Benchmark output is stored in `evaluation_results.csv`.

---

## References

- D.-C. Wu and W.-H. Tsai, "A Steganographic Method for Images by Pixel-Value Differencing"
- J. Fridrich, M. Goljan, and R. Du, "Detecting LSB Steganography in Color and Gray-Scale Images"
- A. Westfeld and A. Pfitzmann, "Attacks on Steganographic Systems"
- NIST SP 800-38D, "Recommendation for Block Cipher Modes of Operation: GCM and GMAC"
- RFC 8018, "PKCS #5: Password-Based Cryptography Specification Version 2.1"
