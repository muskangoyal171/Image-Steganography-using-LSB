import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * ExperimentRunner conducts automated empirical evaluations comparing
 * LSB and PVD steganography across 1%, 5%, 10%, and 20% payload capacities.
 *
 * <p><b>Evaluated Metrics:</b></p>
 * <ul>
 *   <li><b>Timing:</b> Embedding time (ms), extraction time (ms), steganalysis time (ms).</li>
 *   <li><b>Fidelity & Quality:</b> Mean Squared Error (MSE), Peak Signal-to-Noise Ratio (PSNR in dB),
 *       and Structural Similarity Index (SSIM).</li>
 *   <li><b>Extraction & Integrity Success:</b> Verifies that the extracted plaintext matches the
 *       original secret text and passes AES-GCM authentication.</li>
 *   <li><b>Steganalysis Resistance:</b> LSB suspicion %, Chi-Square PoV probability %, RS estimated
 *       payload %, and DCT Benford Chi-square.</li>
 *   <li><b>Export:</b> Automatically exports complete benchmark datasets to CSV.</li>
 * </ul>
 */
public class ExperimentRunner {

    public static final int[] PAYLOAD_PERCENTAGES = {1, 5, 10, 20};
    public static final String DEFAULT_PASSWORD = "BenchmarkSecretKey#2026!";

    /**
     * Executes the experimental evaluation on the specified cover image.
     *
     * @param imagePath Path to the cover image.
     * @param csvOutputPath Path to save the exported CSV file.
     * @return List of ExperimentResult objects.
     * @throws Exception If image loading or benchmarking fails.
     */
    public static List<ExperimentResult> runExperiments(String imagePath, String csvOutputPath) throws Exception {
        File file = new File(imagePath);
        if (!file.exists()) {
            throw new IOException("Cover image not found: " + imagePath);
        }

        BufferedImage originalImage = ImageIO.read(file);
        if (originalImage == null) {
            throw new IOException("Failed to parse image file: " + imagePath);
        }

        int width = originalImage.getWidth();
        int height = originalImage.getHeight();
        int totalPixels = width * height;

        // Base capacity for 3-pixel LSB: (totalPixels / 3) Base64 characters
        // Accounting for Base64 expansion (4/3) and 44 bytes header (Salt + IV + Tag)
        int maxLsbBase64Chars = totalPixels / 3;
        int maxPlaintextChars = Math.max(50, (int) ((maxLsbBase64Chars * 0.75) - 60));

        System.out.println("========================================================================================");
        System.out.println("               AUTOMATED EXPERIMENTAL EVALUATION: LSB vs PVD                            ");
        System.out.println("========================================================================================");
        System.out.println(String.format(" Cover Image       : %s", imagePath));
        System.out.println(String.format(" Image Dimensions  : %d x %d (%d pixels)", width, height, totalPixels));
        System.out.println(String.format(" Max Safe Payload  : ~%d characters", maxPlaintextChars));
        System.out.println(String.format(" Tested Rates      : 1%%, 5%%, 10%%, 20%%"));
        System.out.println(String.format(" Security Protocol : AES-256-GCM + PBKDF2WithHmacSHA256 (65,536 iterations)"));
        System.out.println("========================================================================================\n");

        List<ExperimentResult> results = new ArrayList<>();
        String[] algorithms = {"LSB", "PVD"};

        TextEncryptor textEncryptor = new TextEncryptor();
        TextDecryptor textDecryptor = new TextDecryptor();

        for (String algo : algorithms) {
            System.out.println(String.format(">>> Evaluating Algorithm: %s...", algo));

            for (int pct : PAYLOAD_PERCENTAGES) {
                int charCount = Math.max(16, (int) Math.round(maxPlaintextChars * (pct / 100.0)));
                String plaintext = generateSyntheticMessage(charCount);
                int payloadBits = plaintext.length() * 8;

                System.out.print(String.format("   • %2d%% Payload (%5d chars) -> ", pct, charCount));

                // 1. Embedding measurement
                long tStart = System.currentTimeMillis();
                String encryptedPayload = textEncryptor.encrypt(plaintext, DEFAULT_PASSWORD);

                BufferedImage stegoImage;
                if (algo.equals("LSB")) {
                    stegoImage = EmbedLSB.embedToBufferedImage(originalImage, encryptedPayload);
                } else {
                    stegoImage = PvdSteganography.embed(originalImage, encryptedPayload);
                }
                long embedTime = System.currentTimeMillis() - tStart;

                // 2. Visual Quality metrics
                double mse = ImageQualityMetrics.calculateMSE(originalImage, stegoImage);
                double psnr = ImageQualityMetrics.calculatePSNR(originalImage, stegoImage);
                double ssim = ImageQualityMetrics.calculateSSIM(originalImage, stegoImage);

                // 3. Extraction & Integrity measurement
                tStart = System.currentTimeMillis();
                String recoveredText = "";
                boolean extractionSuccess = false;
                try {
                    if (algo.equals("LSB")) {
                        recoveredText = ExtractLSB.extractFromBufferedImage(stegoImage, DEFAULT_PASSWORD);
                    } else {
                        String extractedEncrypted = PvdSteganography.extract(stegoImage);
                        recoveredText = textDecryptor.decrypt(extractedEncrypted, DEFAULT_PASSWORD);
                    }
                    extractionSuccess = plaintext.equals(recoveredText);
                } catch (Exception e) {
                    extractionSuccess = false;
                }
                long extractTime = System.currentTimeMillis() - tStart;

                // 4. Steganalysis measurement
                tStart = System.currentTimeMillis();
                SteganalysisReport report = Steganalyzer.analyze(stegoImage, algo + "_" + pct + "%");
                long analysisTime = System.currentTimeMillis() - tStart;

                double lsbSuspicion = report.getLsbAnalysis().getSuspicionScore();
                double chiSquareProb = report.getChiSquareAnalysis().getOverallProbability() * 100.0;
                double rsEstPayload = report.getRsAnalysis().getEstimatedPayloadRatio() * 100.0;
                double dctBenford = report.getDctAnalysis().getBenfordChiSquare();
                double overallSuspicion = report.getOverallSuspicionScore();

                ExperimentResult res = new ExperimentResult(
                        algo, pct, charCount, payloadBits,
                        embedTime, extractTime, analysisTime,
                        extractionSuccess, mse, psnr, ssim,
                        lsbSuspicion, chiSquareProb, rsEstPayload, dctBenford, overallSuspicion
                );
                results.add(res);

                System.out.println(String.format("Embed: %3dms | Extract: %3dms | PSNR: %5.2fdB | SSIM: %.4f | Extract Success: %s | Suspicion: %5.1f%%",
                        embedTime, extractTime, psnr, ssim, (extractionSuccess ? "PASS" : "FAIL"), overallSuspicion));
            }
            System.out.println();
        }

        // Export to CSV
        exportToCsv(results, csvOutputPath);
        System.out.println("✅ Experimental data successfully exported to: " + csvOutputPath + "\n");

        // Print Formatted Comparison Table
        printComparisonTable(results);

        return results;
    }

    /**
     * Prints a comparative ASCII table summarizing all findings.
     */
    public static void printComparisonTable(List<ExperimentResult> results) {
        System.out.println("============================================================================================================================");
        System.out.println("                                         EXPERIMENTAL RESULTS COMPARISON TABLE                                              ");
        System.out.println("============================================================================================================================");
        System.out.println(String.format("%-5s | %-7s | %-10s | %-11s | %-12s | %-8s | %-9s | %-7s | %-9s | %-9s | %-10s",
                "Algo", "Payload", "Embed(ms)", "Extract(ms)", "Analysis(ms)", "Success", "PSNR(dB)", "SSIM", "RS Est%", "Chi-Sq%", "Suspicion%"));
        System.out.println("----------------------------------------------------------------------------------------------------------------------------");

        for (ExperimentResult r : results) {
            System.out.println(String.format("%-5s | %-7s | %-10d | %-11d | %-12d | %-8s | %-9.2f | %-7.4f | %-9.2f | %-9.2f | %-10.1f",
                    r.getAlgorithm(),
                    r.getPayloadPercentage() + "%",
                    r.getEmbeddingTimeMs(),
                    r.getExtractionTimeMs(),
                    r.getAnalysisTimeMs(),
                    r.isExtractionSuccess() ? "PASS" : "FAIL",
                    r.getPsnr(),
                    r.getSsim(),
                    r.getRsEstimatedPayload(),
                    r.getChiSquareProb(),
                    r.getOverallSuspicion()));
        }
        System.out.println("============================================================================================================================\n");
    }

    /**
     * Exports experiment records to CSV.
     */
    public static void exportToCsv(List<ExperimentResult> results, String csvPath) throws IOException {
        File file = new File(csvPath);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        try (PrintWriter writer = new PrintWriter(new FileWriter(file))) {
            writer.println(ExperimentResult.getCsvHeader());
            for (ExperimentResult r : results) {
                writer.println(r.toCsvRow());
            }
        }
    }

    private static String generateSyntheticMessage(int charLength) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,!?-";
        StringBuilder sb = new StringBuilder(charLength);
        Random rng = new Random(42 + charLength); // Deterministic seed for reproducible evaluation
        for (int i = 0; i < charLength; i++) {
            sb.append(alphabet.charAt(rng.nextInt(alphabet.length())));
        }
        return sb.toString();
    }
}

