import java.awt.image.BufferedImage;

/**
 * RSAnalysis implements the Regular-Singular (RS) Steganalysis algorithm
 * invented by Jessica Fridrich, Miroslav Goljan, and Rui Du.
 *
 * <p><b>Theoretical Background:</b></p>
 * <ul>
 *   <li>RS analysis is one of the most reliable and precise spatial-domain steganalysis techniques
 *       for detecting LSB embedding and estimating the hidden message length.</li>
 *   <li>The image is partitioned into non-overlapping groups \(G = (x_1, x_2, x_3, x_4)\) of \(2 \times 2\) pixels.</li>
 *   <li>A discrimination function \(f(G)\) measures spatial smoothness / local variation:
 *       \[ f(G) = |x_1 - x_2| + |x_2 - x_4| + |x_4 - x_3| + |x_3 - x_1| \]</li>
 *   <li>Groups are categorized under positive mask \(M = [0, 1, 1, 0]\) and negative mask \(-M\):
 *       <ul>
 *         <li><b>Regular Group (\(R\)):</b> \( f(F(G)) > f(G) \)</li>
 *         <li><b>Singular Group (\(S\)):</b> \( f(F(G)) < f(G) \)</li>
 *         <li><b>Unusable Group (\(U\)):</b> \( f(F(G)) == f(G) \)</li>
 *       </ul>
 *   </li>
 *   <li>In a natural, uncompressed cover image:
 *       \[ R_M \approx R_{-M} \quad \text{and} \quad S_M \approx S_{-M} \]</li>
 *   <li>As LSB embedding rate increases, \(R_M\) and \(S_M\) converge towards each other,
 *       while \(R_{-M}\) and \(S_{-M}\) diverge.</li>
 *   <li>By evaluating the parameters after inverting all LSBs and solving the resulting
 *       quadratic polynomial \(a x^2 + b x + c = 0\), the hidden payload ratio \(p \in [0.0, 1.0]\)
 *       (estimated percentage of modified pixels) is precisely recovered.</li>
 * </ul>
 */
public class RSAnalysis {

    private final double rM;
    private final double sM;
    private final double rMinusM;
    private final double sMinusM;
    private final double estimatedPayloadRatio; // 0.0 to 1.0 (0% to 100%)
    private final double suspicionScore;        // 0.0 to 100.0%

    public RSAnalysis(double rM, double sM, double rMinusM, double sMinusM,
                      double estimatedPayloadRatio, double suspicionScore) {
        this.rM = rM;
        this.sM = sM;
        this.rMinusM = rMinusM;
        this.sMinusM = sMinusM;
        this.estimatedPayloadRatio = estimatedPayloadRatio;
        this.suspicionScore = suspicionScore;
    }

    /**
     * Executes RS steganalysis on the input image.
     *
     * @param image The BufferedImage to examine.
     * @return RSAnalysis containing group ratios, estimated payload ratio, and suspicion score.
     */
    public static RSAnalysis analyze(BufferedImage image) {
        int width = image.getWidth();
        int height = image.getHeight();

        // Convert image to grayscale luminance grid for spatial correlation
        int[][] pixels = new int[width][height];
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int rgb = image.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;
                // ITU-R BT.601 luminance
                pixels[x][y] = (int) Math.round(0.299 * r + 0.587 * g + 0.114 * b);
            }
        }

        // Mask definition for 2x2 blocks: M = [0, 1; 1, 0]
        int[][] maskM = {
                {0, 1},
                {1, 0}
        };

        // 1. Initial pass on original image
        RSGroupCounts counts0 = countGroups(pixels, width, height, maskM);

        // 2. Second pass on image with all LSBs flipped (F1 transformation)
        int[][] invertedPixels = new int[width][height];
        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                invertedPixels[x][y] = flipPos(pixels[x][y]);
            }
        }
        RSGroupCounts counts1 = countGroups(invertedPixels, width, height, maskM);

        // Calculate differences
        double d0 = counts0.rM - counts0.sM;
        double dMinus0 = counts0.rMinusM - counts0.sMinusM;
        double d1 = counts1.rM - counts1.sM;
        double dMinus1 = counts1.rMinusM - counts1.sMinusM;

        // Quadratic equation coefficients: a*x^2 + b*x + c = 0
        double a = 2.0 * (d1 + d0);
        double b = (dMinus0 - d0) - (d1 + dMinus1);
        double c = d0 - dMinus0;

        double xRoot = 0.0;
        if (Math.abs(a) < 1.0e-7) {
            // Linear case
            if (Math.abs(b) > 1.0e-7) {
                xRoot = -c / b;
            }
        } else {
            double discriminant = b * b - 4.0 * a * c;
            if (discriminant >= 0.0) {
                double root1 = (-b + Math.sqrt(discriminant)) / (2.0 * a);
                double root2 = (-b - Math.sqrt(discriminant)) / (2.0 * a);
                // Choose root with smaller absolute value
                xRoot = (Math.abs(root1) <= Math.abs(root2)) ? root1 : root2;
            }
        }

        // Estimated embedding rate p = x / (x - 0.5)
        double estimatedPayload = 0.0;
        if (Math.abs(xRoot - 0.5) > 1.0e-5) {
            estimatedPayload = xRoot / (xRoot - 0.5);
        }

        if (Double.isNaN(estimatedPayload) || estimatedPayload < 0.0) {
            estimatedPayload = 0.0;
        } else if (estimatedPayload > 1.0) {
            estimatedPayload = 1.0;
        }

        // Suspicion score based on symmetry breakdown (|d0 - dMinus0|) and estimated payload
        double asymmetry = Math.abs(d0 - dMinus0);
        double asymmetryScore = Math.min(100.0, (asymmetry / 0.05) * 100.0);
        double payloadScore = estimatedPayload * 100.0;

        double suspicion = (payloadScore * 0.70) + (asymmetryScore * 0.30);
        suspicion = Math.min(100.0, Math.max(0.0, suspicion));

        return new RSAnalysis(counts0.rM, counts0.sM, counts0.rMinusM, counts0.sMinusM,
                estimatedPayload, suspicion);
    }

    private static class RSGroupCounts {
        final double rM;
        final double sM;
        final double rMinusM;
        final double sMinusM;

        RSGroupCounts(double rM, double sM, double rMinusM, double sMinusM) {
            this.rM = rM;
            this.sM = sM;
            this.rMinusM = rMinusM;
            this.sMinusM = sMinusM;
        }
    }

    private static RSGroupCounts countGroups(int[][] grid, int width, int height, int[][] mask) {
        int rMCount = 0;
        int sMCount = 0;
        int rMinusMCount = 0;
        int sMinusMCount = 0;
        int totalGroups = 0;

        for (int x = 0; x < width - 1; x += 2) {
            for (int y = 0; y < height - 1; y += 2) {
                int x1 = grid[x][y];
                int x2 = grid[x + 1][y];
                int x3 = grid[x][y + 1];
                int x4 = grid[x + 1][y + 1];

                double fOrig = variation(x1, x2, x3, x4);

                // Positive mask M
                int mX1 = applyFlipping(x1, mask[0][0]);
                int mX2 = applyFlipping(x2, mask[1][0]);
                int mX3 = applyFlipping(x3, mask[0][1]);
                int mX4 = applyFlipping(x4, mask[1][1]);
                double fM = variation(mX1, mX2, mX3, mX4);

                if (fM > fOrig) rMCount++;
                else if (fM < fOrig) sMCount++;

                // Negative mask -M
                int negX1 = applyFlipping(x1, -mask[0][0]);
                int negX2 = applyFlipping(x2, -mask[1][0]);
                int negX3 = applyFlipping(x3, -mask[0][1]);
                int negX4 = applyFlipping(x4, -mask[1][1]);
                double fNegM = variation(negX1, negX2, negX3, negX4);

                if (fNegM > fOrig) rMinusMCount++;
                else if (fNegM < fOrig) sMinusMCount++;

                totalGroups++;
            }
        }

        if (totalGroups == 0) {
            return new RSGroupCounts(0, 0, 0, 0);
        }

        return new RSGroupCounts(
                (double) rMCount / totalGroups,
                (double) sMCount / totalGroups,
                (double) rMinusMCount / totalGroups,
                (double) sMinusMCount / totalGroups
        );
    }

    private static double variation(int x1, int x2, int x3, int x4) {
        return Math.abs(x1 - x2) + Math.abs(x2 - x4) + Math.abs(x4 - x3) + Math.abs(x3 - x1);
    }

    private static int applyFlipping(int value, int maskValue) {
        if (maskValue == 1) {
            return flipPos(value);
        } else if (maskValue == -1) {
            return flipNeg(value);
        }
        return value;
    }

    /**
     * F1 operation (invert LSB): 0 <-> 1, 2 <-> 3, etc.
     */
    private static int flipPos(int x) {
        return x ^ 1;
    }

    /**
     * F-1 operation: -1 <-> 0, 1 <-> 2, etc.
     */
    private static int flipNeg(int x) {
        if ((x & 1) == 1) {
            return Math.min(255, x + 1);
        } else {
            return Math.max(0, x - 1);
        }
    }

    public double getrM() {
        return rM;
    }

    public double getsM() {
        return sM;
    }

    public double getrMinusM() {
        return rMinusM;
    }

    public double getsMinusM() {
        return sMinusM;
    }

    public double getEstimatedPayloadRatio() {
        return estimatedPayloadRatio;
    }

    public double getSuspicionScore() {
        return suspicionScore;
    }
}

