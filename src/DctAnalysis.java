import java.awt.image.BufferedImage;

/**
 * DctAnalysis evaluates Discrete Cosine Transform (DCT) coefficient distributions,
 * compliance with Benford's Law, high-frequency energy ratios, and blockiness metrics.
 *
 * <p><b>Techniques & Indicators:</b></p>
 * <ul>
 *   <li><b>Block-based 2D DCT:</b> Computes standard \(8 \times 8\) block forward DCT across the luminance plane.</li>
 *   <li><b>Benford's Law for First Digits:</b> In natural images, the first significant digit
 *       \(d \in \{1, \dots, 9\}\) of non-zero AC DCT coefficients follows the logarithmic distribution:
 *       \[ P(d) = \log_{10}\left(1 + \frac{1}{d}\right) \]
 *       Deviations measured via Chi-Square goodness-of-fit (\(\chi_{\text{Benford}}^2\)) indicate
 *       steganographic perturbation, double compression, or synthetic manipulation.</li>
 *   <li><b>High-Frequency AC Energy Ratio:</b> Spatial LSB noise significantly increases the variance
 *       and energy of high-frequency DCT coefficients (\(u + v \ge 8\)).</li>
 *   <li><b>Blockiness Metric:</b> Evaluates inter-block boundary discontinuity versus intra-block
 *       gradients across \(8 \times 8\) grid boundaries.</li>
 * </ul>
 */
public class DctAnalysis {

    private final double benfordChiSquare;
    private final double benfordPValue;
    private final double highFrequencyEnergyRatio;
    private final double blockinessMetric;
    private final double suspicionScore; // 0.0 to 100.0%

    // Benford's Law theoretical probabilities for digits 1..9
    private static final double[] BENFORD_PROBABILITIES = {
            0.30103, // 1
            0.17609, // 2
            0.12494, // 3
            0.09691, // 4
            0.07918, // 5
            0.06695, // 6
            0.05799, // 7
            0.05115, // 8
            0.04576  // 9
    };

    public DctAnalysis(double benfordChiSquare, double benfordPValue,
                       double highFrequencyEnergyRatio, double blockinessMetric,
                       double suspicionScore) {
        this.benfordChiSquare = benfordChiSquare;
        this.benfordPValue = benfordPValue;
        this.highFrequencyEnergyRatio = highFrequencyEnergyRatio;
        this.blockinessMetric = blockinessMetric;
        this.suspicionScore = suspicionScore;
    }

    /**
     * Executes DCT coefficient analysis on the given image.
     *
     * @param image The image to inspect.
     * @return DctAnalysis result.
     */
    public static DctAnalysis analyze(BufferedImage image) {
        int width = image.getWidth();
        int height = image.getHeight();

        int blocksX = width / 8;
        int blocksY = height / 8;

        if (blocksX == 0 || blocksY == 0) {
            return new DctAnalysis(0, 1.0, 0, 1.0, 0.0);
        }

        // Extract luminance matrix
        double[][] luminance = new double[width][height];
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int rgb = image.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;
                luminance[x][y] = (0.299 * r + 0.587 * g + 0.114 * b) - 128.0; // Level shift by -128
            }
        }

        int[] digitCounts = new int[9]; // Digits 1 to 9
        int totalAcCoefficients = 0;
        double totalAcEnergy = 0.0;
        double highFreqAcEnergy = 0.0;

        double[][] block = new double[8][8];
        double[][] dctCoeffs = new double[8][8];

        for (int by = 0; by < blocksY; by++) {
            for (int bx = 0; bx < blocksX; bx++) {
                // Load 8x8 block
                for (int y = 0; y < 8; y++) {
                    for (int x = 0; x < 8; x++) {
                        block[x][y] = luminance[bx * 8 + x][by * 8 + y];
                    }
                }

                // Compute 2D DCT
                forwardDct8x8(block, dctCoeffs);

                // Analyze AC coefficients ((u, v) != (0, 0))
                for (int u = 0; u < 8; u++) {
                    for (int v = 0; v < 8; v++) {
                        if (u == 0 && v == 0) continue; // Skip DC coefficient

                        double val = dctCoeffs[u][v];
                        double energy = val * val;
                        totalAcEnergy += energy;

                        if (u + v >= 8) {
                            highFreqAcEnergy += energy;
                        }

                        // First significant digit for Benford's Law
                        int rounded = (int) Math.round(Math.abs(val));
                        if (rounded > 0) {
                            int firstDigit = getFirstSignificantDigit(rounded);
                            if (firstDigit >= 1 && firstDigit <= 9) {
                                digitCounts[firstDigit - 1]++;
                                totalAcCoefficients++;
                            }
                        }
                    }
                }
            }
        }

        // 1. Benford's Law Chi-Square Test
        double benfordChiSq = 0.0;
        if (totalAcCoefficients >= 100) {
            for (int d = 0; d < 9; d++) {
                double observed = digitCounts[d];
                double expected = totalAcCoefficients * BENFORD_PROBABILITIES[d];
                double diff = observed - expected;
                benfordChiSq += (diff * diff) / expected;
            }
        }

        // Degrees of freedom = 9 - 1 = 8
        double benfordP = ChiSquareAnalysis.regularizedIncompleteGammaP(4.0, benfordChiSq / 2.0);
        double benfordPValue = 1.0 - benfordP; // Small p-value indicates deviation from Benford's law

        // 2. High-Frequency Energy Ratio
        double hfRatio = (totalAcEnergy > 0) ? (highFreqAcEnergy / totalAcEnergy) : 0.0;

        // 3. Blockiness Metric (boundary discontinuity)
        double blockiness = calculateBlockiness(luminance, width, height, blocksX, blocksY);

        // 4. Suspicion Scoring
        // Anomalies:
        // - Benford Chi-square > 20.0 indicates significant perturbation
        // - Elevated high-frequency energy ratio (> 0.25)
        // - Blockiness deviation from 1.0
        double benfordSuspicion = Math.min(100.0, (benfordChiSq / 30.0) * 100.0);
        double hfSuspicion = Math.min(100.0, Math.max(0.0, (hfRatio - 0.15) / 0.25 * 100.0));
        double blockinessSuspicion = Math.min(100.0, Math.abs(blockiness - 1.0) * 80.0);

        double suspicion = (benfordSuspicion * 0.50) + (hfSuspicion * 0.35) + (blockinessSuspicion * 0.15);
        suspicion = Math.min(100.0, Math.max(0.0, suspicion));

        return new DctAnalysis(benfordChiSq, benfordPValue, hfRatio, blockiness, suspicion);
    }

    /**
     * Standard 8x8 2D Discrete Cosine Transform (orthonormal).
     */
    private static void forwardDct8x8(double[][] input, double[][] output) {
        for (int u = 0; u < 8; u++) {
            double cu = (u == 0) ? (1.0 / Math.sqrt(2.0)) : 1.0;
            for (int v = 0; v < 8; v++) {
                double cv = (v == 0) ? (1.0 / Math.sqrt(2.0)) : 1.0;
                double sum = 0.0;
                for (int x = 0; x < 8; x++) {
                    double cosX = Math.cos(((2.0 * x + 1.0) * u * Math.PI) / 16.0);
                    for (int y = 0; y < 8; y++) {
                        double cosY = Math.cos(((2.0 * y + 1.0) * v * Math.PI) / 16.0);
                        sum += input[x][y] * cosX * cosY;
                    }
                }
                output[u][v] = 0.25 * cu * cv * sum;
            }
        }
    }

    private static int getFirstSignificantDigit(int num) {
        while (num >= 10) {
            num /= 10;
        }
        return num;
    }

    private static double calculateBlockiness(double[][] lum, int width, int height, int bx, int by) {
        double boundaryDiff = 0.0;
        double interiorDiff = 0.0;
        int countB = 0;
        int countI = 0;

        for (int y = 0; y < height; y++) {
            for (int x = 1; x < width - 1; x++) {
                double diff = Math.abs(lum[x][y] - lum[x + 1][y]);
                if (x % 8 == 7) {
                    boundaryDiff += diff;
                    countB++;
                } else if (x % 8 == 6) {
                    interiorDiff += diff;
                    countI++;
                }
            }
        }

        if (interiorDiff == 0 || countI == 0 || countB == 0) return 1.0;
        return (boundaryDiff / countB) / (interiorDiff / countI);
    }

    public double getBenfordChiSquare() {
        return benfordChiSquare;
    }

    public double getBenfordPValue() {
        return benfordPValue;
    }

    public double getHighFrequencyEnergyRatio() {
        return highFrequencyEnergyRatio;
    }

    public double getBlockinessMetric() {
        return blockinessMetric;
    }

    public double getSuspicionScore() {
        return suspicionScore;
    }
}

