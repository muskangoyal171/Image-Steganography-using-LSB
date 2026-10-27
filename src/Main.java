import java.io.File;
import java.util.Scanner;

/**
 * Main application console interface for Secure Image Steganography & Steganalysis.
 *
 * <p>Supported Operations:
 * <ul>
 *   <li><b>A:</b> AES-256-GCM + PBKDF2 authenticated encryption & LSB embedding.</li>
 *   <li><b>B:</b> Extraction, GMAC integrity authentication, and decryption.</li>
 *   <li><b>C:</b> Steganalysis Suite (LSB statistics, Chi-Square PoV, RS analysis, DCT coefficient analysis).</li>
 *   <li><b>D:</b> Experiments & Evaluation (Compare LSB vs PVD across 1%, 5%, 10%, 20% payload sizes -> CSV export).</li>
 * </ul>
 */
public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("=========================================================================");
        System.out.println("     SECURE IMAGE STEGANOGRAPHY & STEGANALYSIS SUITE (JAVA 17+)         ");
        System.out.println("=========================================================================");
        System.out.println("What would you like to do? (A/B/C/D)");
        System.out.println("  A: Encrypt and embed a secret message into an image");
        System.out.println("  B: Extract, authenticate, and decrypt a message from an image");
        System.out.println("  C: Run Steganalysis on an image (LSB, Chi-Square, RS, DCT analysis)");
        System.out.println("  D: Run Experiments & Benchmark (Compare LSB vs PVD at 1%, 5%, 10%, 20% -> CSV)");
        System.out.print("Select option (A/B/C/D): ");

        String action = scanner.nextLine().trim();

        if (action.equalsIgnoreCase("A")) {
            System.out.println("\n-------------------------------------------------------------------------");
            System.out.println(" [Option A] EMBED SECRET MESSAGE");
            System.out.println("-------------------------------------------------------------------------");

            System.out.print("1. Enter the secret message to hide:\n> ");
            String message = scanner.nextLine();

            System.out.print("2. Enter a secret password for encryption:\n> ");
            String password = scanner.nextLine();

            System.out.print("3. Enter the cover image path (e.g., pictures/input/cute_dog.png):\n> ");
            String inputPath = scanner.nextLine().trim();

            System.out.print("4. Enter the destination path for stego-image (e.g., pictures/stego.png):\n> ");
            String outputPath = scanner.nextLine().trim();

            Generate_image(message, password, inputPath, outputPath);

        } else if (action.equalsIgnoreCase("B")) {
            System.out.println("\n-------------------------------------------------------------------------");
            System.out.println(" [Option B] EXTRACT & DECRYPT SECRET MESSAGE");
            System.out.println("-------------------------------------------------------------------------");

            System.out.print("1. Enter the path of the stego-image:\n> ");
            String imagePath = scanner.nextLine().trim();

            System.out.print("2. Enter the secret password for decryption:\n> ");
            String password = scanner.nextLine();

            Extract_text(imagePath, password);

        } else if (action.equalsIgnoreCase("C")) {
            System.out.println("\n-------------------------------------------------------------------------");
            System.out.println(" [Option C] RUN STEGANALYSIS SUITE");
            System.out.println("-------------------------------------------------------------------------");

            System.out.print("Enter the image path to analyze (e.g., pictures/input/cute_dog.png):\n> ");
            String imagePath = scanner.nextLine().trim();

            Run_steganalysis(imagePath);

        } else if (action.equalsIgnoreCase("D")) {
            System.out.println("\n-------------------------------------------------------------------------");
            System.out.println(" [Option D] RUN EXPERIMENTS & EVALUATION BENCHMARK");
            System.out.println("-------------------------------------------------------------------------");

            System.out.print("Enter cover image path (or press Enter for default 'pictures/input/cute_dog.png'):\n> ");
            String imagePath = scanner.nextLine().trim();
            if (imagePath.isEmpty()) {
                imagePath = "pictures/input/cute_dog.png";
            }

            System.out.print("Enter CSV output path (or press Enter for default 'evaluation_results.csv'):\n> ");
            String csvPath = scanner.nextLine().trim();
            if (csvPath.isEmpty()) {
                csvPath = "evaluation_results.csv";
            }

            Run_experiments(imagePath, csvPath);

        } else {
            System.out.println("\n❌ Invalid choice! Please restart and enter 'A', 'B', 'C', or 'D'.");
        }

        scanner.close();
    }

    /**
     * Encrypts the plaintext message using AES-256-GCM with a key derived via PBKDF2,
     * then embeds the resulting payload into the cover image using LSB.
     *
     * @param message Plaintext message to hide.
     * @param password Secret password for key derivation.
     * @param input_path Path to the cover image.
     * @param output_path Destination path for the stego-image.
     */
    public static void Generate_image(String message, String password, String input_path, String output_path) {
        try {
            File imageFile = new File(input_path);
            if (!imageFile.exists()) {
                System.err.println("\n❌ Error: Cover image file not found at: " + input_path);
                return;
            }

            System.out.println("\n[1/3] Encrypting message with AES-256-GCM...");
            TextEncryptor textEncryptor = new TextEncryptor();
            String encryptedPayload = textEncryptor.encrypt(message, password);

            System.out.println("[2/3] Embedding encrypted payload into image pixels via LSB...");
            EmbedLSB.Embed(imageFile, encryptedPayload, output_path);

            System.out.println("[3/3] Success! Stego-image generated at: " + output_path);
            System.out.println("-------------------------------------------------------------------------");
            System.out.println("🔒 Security Summary:");
            System.out.println("  • Cipher: AES-256-GCM (Authenticated Encryption with Associated Data)");
            System.out.println("  • Key Derivation: PBKDF2WithHmacSHA256 (65,536 iterations, 16-byte random salt)");
            System.out.println("  • IV: 12-byte cryptographically secure unique nonce");
            System.out.println("  • Integrity: 128-bit GMAC Authentication Tag embedded");
            System.out.println("  • Steganography: LSB 3-pixel encoding (lossless PNG)");
            System.out.println("-------------------------------------------------------------------------");
            System.out.println("Tell your recipient to use option 'B' with the SAME PASSWORD to read the message.");

        } catch (IllegalArgumentException e) {
            System.err.println("\n❌ Validation Error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("\n❌ Error during embedding process: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Extracts the hidden payload from the stego-image, verifies cryptographic integrity,
     * and decrypts the secret message using the password.
     *
     * @param output_path Path to the stego-image.
     * @param password Secret password for key derivation and decryption.
     */
    public static void Extract_text(String output_path, String password) {
        try {
            System.out.println("\n[1/2] Extracting hidden bits from image pixels...");
            String decryptedMessage = ExtractLSB.Extract(output_path, password);

            System.out.println("[2/2] Cryptographic integrity verified! Message successfully authenticated.");
            System.out.println("-------------------------------------------------------------------------");
            System.out.println("✅ INTEGRITY VERIFIED (No tampering detected)");
            System.out.println("Decrypted Secret Message: " + decryptedMessage);
            System.out.println("-------------------------------------------------------------------------");

        } catch (SecurityException e) {
            System.err.println("\n-------------------------------------------------------------------------");
            System.err.println("❌ SECURITY ALERT / INTEGRITY VERIFICATION FAILED!");
            System.err.println("Reason: " + e.getMessage());
            System.err.println("Possible causes:");
            System.err.println("  1. The image pixels or hidden message have been tampered with or modified.");
            System.err.println("  2. An incorrect password was entered.");
            System.err.println("  3. The image was saved in a lossy format (e.g., JPEG compression altered bits).");
            System.err.println("-------------------------------------------------------------------------");
        } catch (Exception e) {
            System.err.println("\n❌ Error during extraction process: " + e.getMessage());
        }
    }

    /**
     * Runs full steganalysis on an image (LSB, Chi-Square, RS, and DCT coefficient analysis).
     *
     * @param image_path Path to the target image file.
     */
    public static void Run_steganalysis(String image_path) {
        try {
            System.out.println("\nRunning Steganalysis Suite on: " + image_path);
            System.out.println("  [1/4] Calculating LSB statistical distributions & spatial autocorrelation...");
            System.out.println("  [2/4] Executing Westfeld & Pfitzmann Pairs-of-Values Chi-Square attack...");
            System.out.println("  [3/4] Performing Fridrich et al. Regular/Singular (RS) steganalysis...");
            System.out.println("  [4/4] Performing 2D DCT Block Transform & Benford's Law analysis...");

            SteganalysisReport report = Steganalyzer.analyze(image_path);
            System.out.println(report.generateFormattedReport());

        } catch (Exception e) {
            System.err.println("\n❌ Error during steganalysis: " + e.getMessage());
        }
    }

    /**
     * Executes automated benchmark experiments comparing LSB and PVD at 1%, 5%, 10%, 20% payload sizes
     * and exports quantitative results to CSV.
     *
     * @param image_path Cover image path.
     * @param csv_path Output CSV file path.
     */
    public static void Run_experiments(String image_path, String csv_path) {
        try {
            ExperimentRunner.runExperiments(image_path, csv_path);
        } catch (Exception e) {
            System.err.println("\n❌ Error during experimental evaluation: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
