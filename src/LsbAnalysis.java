import java.awt.image.BufferedImage;

/**
 * LsbAnalysis performs statistical evaluation on the Least Significant Bit (LSB) plane
 * of digital images.
 *
 * <p><b>Methodology:</b></p>
 * <ul>
 *   <li><b>0/1 Bit Frequency:</b> Natural images typically exhibit non-uniform LSB distributions
 *       due to camera sensor characteristics, lighting, and textures. In contrast, encrypted
 *       or compressed steganographic payloads (such as AES-GCM) exhibit an almost exact
 *       50/50 balance of 0s and 1s.</li>
 *   <li><b>Shannon Entropy:</b> Evaluates the information entropy of the LSB plane:
 *       \( H = -p_0 \log_2(p_0) - p_1 \log_2(p_1) \). For encrypted payloads, \( H \approx 1.0000 \).</li>
 *   <li><b>Spatial Autocorrelation:</b> In natural images, adjacent pixel LSBs are correlated (\( \rho > 0 \)).
 *       LSB substitution introduces independent random bits, causing autocorrelation to drop near zero.</li>
 *   <li><b>Wald-Wolfowitz Runs Test:</b> Evaluates whether consecutive runs of identical bits
 *       are consistent with independent random variables.</li>
 * </ul>
 */
public class LsbAnalysis {

    private final double bitOneRatio;
    private final double entropy;
    private final double horizontalAutocorrelation;
    private final double verticalAutocorrelation;
    private final double runsZScore;
    private final double suspicionScore; // 0.0 to 100.0%

    public LsbAnalysis(double bitOneRatio, double entropy, double horizontalAutocorrelation,
                       double verticalAutocorrelation, double runsZScore, double suspicionScore) {
        this.bitOneRatio = bitOneRatio;
        this.entropy = entropy;
        this.horizontalAutocorrelation = horizontalAutocorrelation;
        this.verticalAutocorrelation = verticalAutocorrelation;
        this.runsZScore = runsZScore;
        this.suspicionScore = suspicionScore;
    }

    /**
     * Executes LSB statistical analysis on the given image.
     *
     * @param image The BufferedImage to inspect.
     * @return LsbAnalysis result object.
     */
    public static LsbAnalysis analyze(BufferedImage image) {
        int width = image.getWidth();
        int height = image.getHeight();
        int totalPixels = width * height;

        int totalBits = totalPixels * 3; // R, G, B channels
        int onesCount = 0;

        // Bit arrays for spatial autocorrelation (using luminance/green channel)
        int[][] lsbMatrix = new int[width][height];

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int rgb = image.getRGB(x, y);
                int rLsb = (rgb >> 16) & 1;
                int gLsb = (rgb >> 8) & 1;
                int bLsb = rgb & 1;

                onesCount += (rLsb + gLsb + bLsb);
                lsbMatrix[x][y] = gLsb; // Green channel has highest luminance weight
            }
        }

        // 1. Bit 1 Ratio
        double p1 = (double) onesCount / totalBits;
        double p0 = 1.0 - p1;

        // 2. Shannon Entropy
        double entropy = 0.0;
        if (p0 > 0 && p1 > 0) {
            entropy = -(p0 * (Math.log(p0) / Math.log(2)) + p1 * (Math.log(p1) / Math.log(2)));
        }

        // 3. Horizontal & Vertical Spatial Autocorrelation (Pearson r on LSB matrix)
        double mean = 0.0;
        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                mean += lsbMatrix[x][y];
            }
        }
        mean /= totalPixels;

        double var = 0.0;
        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                double diff = lsbMatrix[x][y] - mean;
                var += diff * diff;
            }
        }

        double covH = 0.0;
        int countH = 0;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width - 1; x++) {
                covH += (lsbMatrix[x][y] - mean) * (lsbMatrix[x + 1][y] - mean);
                countH++;
            }
        }
        double autoCorrH = (var > 0 && countH > 0) ? (covH / countH) / (var / totalPixels) : 0.0;

        double covV = 0.0;
        int countV = 0;
        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height - 1; y++) {
                covV += (lsbMatrix[x][y] - mean) * (lsbMatrix[x][y + 1] - mean);
                countV++;
            }
        }
        double autoCorrV = (var > 0 && countV > 0) ? (covV / countV) / (var / totalPixels) : 0.0;

        // 4. Wald-Wolfowitz Runs Test on LSB bitstream
        int runs = 1;
        int n1 = 0;
        int n0 = 0;
        int prevBit = lsbMatrix[0][0];
        if (prevBit == 1) n1++; else n0++;

        for (int y = 0; y < height; y++) {
            for (int x = (y == 0 ? 1 : 0); x < width; x++) {
                int bit = lsbMatrix[x][y];
                if (bit == 1) n1++; else n0++;
                if (bit != prevBit) {
                    runs++;
                    prevBit = bit;
                }
            }
        }

        double expectedRuns = 1.0 + (2.0 * n1 * n0) / (double) totalPixels;
        double varRuns = (2.0 * n1 * n0 * (2.0 * n1 * n0 - totalPixels)) /
                ((double) totalPixels * totalPixels * (totalPixels - 1));
        double runsZScore = (varRuns > 0) ? (runs - expectedRuns) / Math.sqrt(varRuns) : 0.0;

        // 5. Compute Suspicion Score (0.0% to 100.0%)
        // Indicators of steganography:
        // - p1 very close to 0.50 (deviation < 0.005)
        // - entropy very close to 1.0000 (> 0.9995)
        // - autocorrelation close to 0 (|autoCorr| < 0.03)
        // - |runsZScore| < 1.96 (consistent with random bitstream)
        double devFromHalf = Math.abs(p1 - 0.5);
        double balanceScore = Math.max(0.0, 100.0 * (1.0 - (devFromHalf / 0.05)));

        double entropyScore = (entropy >= 0.9990) ? 100.0 :
                Math.max(0.0, (entropy - 0.95) / 0.05 * 100.0);

        double avgAutoCorr = (Math.abs(autoCorrH) + Math.abs(autoCorrV)) / 2.0;
        double autoCorrScore = (avgAutoCorr < 0.02) ? 100.0 :
                Math.max(0.0, 100.0 * (1.0 - (avgAutoCorr / 0.20)));

        double runsScore = (Math.abs(runsZScore) < 1.96) ? 80.0 :
                Math.max(0.0, 80.0 * (1.0 - (Math.abs(runsZScore) - 1.96) / 5.0));

        double suspicion = (balanceScore * 0.25) + (entropyScore * 0.35) +
                (autoCorrScore * 0.25) + (runsScore * 0.15);
        suspicion = Math.min(100.0, Math.max(0.0, suspicion));

        return new LsbAnalysis(p1, entropy, autoCorrH, autoCorrV, runsZScore, suspicion);
    }

    public double getBitOneRatio() {
        return bitOneRatio;
    }

    public double getEntropy() {
        return entropy;
    }

    public double getHorizontalAutocorrelation() {
        return horizontalAutocorrelation;
    }

    public double getVerticalAutocorrelation() {
        return verticalAutocorrelation;
    }

    public double getRunsZScore() {
        return runsZScore;
    }

    public double getSuspicionScore() {
        return suspicionScore;
    }
}

