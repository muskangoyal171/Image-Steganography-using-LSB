import java.awt.image.BufferedImage;

/**
 * ChiSquareAnalysis implements the Westfeld & Pfitzmann Pairs of Values (PoV)
 * statistical attack for spatial domain LSB steganography.
 *
 * <p><b>Mathematical Principle:</b></p>
 * <ul>
 *   <li>In natural images, adjacent intensity levels in a Pair of Values (PoV), e.g.,
 *       \((2k, 2k+1)\) such as \((0, 1), (2, 3), \dots, (254, 255)\), have independent
 *       frequencies reflecting scene textures and illumination gradients.</li>
 *   <li>When LSB steganography is applied with pseudo-random or encrypted payload bits,
 *       the probability of an even pixel \(2k\) flipping to \(2k+1\) is 50%, and vice-versa.
 *       This causes the observed counts \(n_{2k}\) and \(n_{2k+1}\) to asymptotically equalize.</li>
 *   <li>The expected frequency for both values is \( n_k^* = \frac{n_{2k} + n_{2k+1}}{2} \).</li>
 *   <li>The Chi-Square statistic evaluates the deviation from equalization:
 *       \[ \chi^2 = \sum_{k=0}^{127} \frac{(n_{2k} - n_k^*)^2}{n_k^*} \]</li>
 *   <li>The probability of embedding \(p\) is calculated using the complementary
 *       cumulative distribution function (regularized upper incomplete gamma function):
 *       \[ p = 1 - P\left(\frac{df}{2}, \frac{\chi^2}{2}\right) \]
 *       When \(p \to 1.0\), equalization is near-perfect, indicating high likelihood of LSB steganography.</li>
 * </ul>
 */
public class ChiSquareAnalysis {

    private final double chiSquareRed;
    private final double chiSquareGreen;
    private final double chiSquareBlue;
    private final double pValueRed;
    private final double pValueGreen;
    private final double pValueBlue;
    private final double overallProbability;
    private final double suspicionScore; // 0.0 to 100.0%

    public ChiSquareAnalysis(double chiSquareRed, double chiSquareGreen, double chiSquareBlue,
                              double pValueRed, double pValueGreen, double pValueBlue,
                              double overallProbability, double suspicionScore) {
        this.chiSquareRed = chiSquareRed;
        this.chiSquareGreen = chiSquareGreen;
        this.chiSquareBlue = chiSquareBlue;
        this.pValueRed = pValueRed;
        this.pValueGreen = pValueGreen;
        this.pValueBlue = pValueBlue;
        this.overallProbability = overallProbability;
        this.suspicionScore = suspicionScore;
    }

    /**
     * Performs Chi-Square PoV steganalysis on the provided image.
     *
     * @param image The image to inspect.
     * @return ChiSquareAnalysis containing statistics and embedding probabilities.
     */
    public static ChiSquareAnalysis analyze(BufferedImage image) {
        int width = image.getWidth();
        int height = image.getHeight();

        int[] histR = new int[256];
        int[] histG = new int[256];
        int[] histB = new int[256];

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int rgb = image.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;

                histR[r]++;
                histG[g]++;
                histB[b]++;
            }
        }

        ChannelResult resR = calculateChannelChiSquare(histR);
        ChannelResult resG = calculateChannelChiSquare(histG);
        ChannelResult resB = calculateChannelChiSquare(histB);

        // In 3-pixel LSB, payload bits are distributed across R, G, and B
        double avgProbability = (resR.pValue + resG.pValue + resB.pValue) / 3.0;
        double maxProbability = Math.max(resR.pValue, Math.max(resG.pValue, resB.pValue));
        double combinedProb = (avgProbability * 0.6) + (maxProbability * 0.4);

        double suspicion = Math.min(100.0, Math.max(0.0, combinedProb * 100.0));

        return new ChiSquareAnalysis(
                resR.chiSquare, resG.chiSquare, resB.chiSquare,
                resR.pValue, resG.pValue, resB.pValue,
                combinedProb, suspicion
        );
    }

    private static class ChannelResult {
        final double chiSquare;
        final double pValue;

        ChannelResult(double chiSquare, double pValue) {
            this.chiSquare = chiSquare;
            this.pValue = pValue;
        }
    }

    private static ChannelResult calculateChannelChiSquare(int[] histogram) {
        double chiSquare = 0.0;
        int activePairs = 0;

        for (int k = 0; k < 128; k++) {
            int n2k = histogram[2 * k];
            int n2k1 = histogram[2 * k + 1];
            double expected = (n2k + n2k1) / 2.0;

            if (expected > 0) {
                double diff = n2k - expected;
                chiSquare += (diff * diff) / expected;
                activePairs++;
            }
        }

        int df = activePairs - 1;
        if (df <= 0) {
            return new ChannelResult(0.0, 0.0);
        }

        // p-value = 1 - regularizedGammaP(df/2, chiSquare/2)
        // High p-value indicates that differences are close to 0 (equalized PoVs)
        double a = df / 2.0;
        double x = chiSquare / 2.0;
        double gammaP = regularizedIncompleteGammaP(a, x);
        double pValue = 1.0 - gammaP;

        // Clean bounds
        if (Double.isNaN(pValue)) pValue = 0.0;
        pValue = Math.min(1.0, Math.max(0.0, pValue));

        return new ChannelResult(chiSquare, pValue);
    }

    /**
     * Computes the regularized lower incomplete gamma function P(a, x) = gamma(a, x) / Gamma(a).
     */
    public static double regularizedIncompleteGammaP(double a, double x) {
        if (x < 0.0 || a <= 0.0) return 0.0;
        if (x == 0.0) return 0.0;

        // Use series expansion for x < a + 1
        if (x < a + 1.0) {
            double ap = a;
            double sum = 1.0 / a;
            double del = sum;
            for (int n = 1; n <= 100; n++) {
                ap += 1.0;
                del *= x / ap;
                sum += del;
                if (Math.abs(del) < Math.abs(sum) * 1.0e-14) {
                    break;
                }
            }
            return sum * Math.exp(-x + a * Math.log(x) - logGamma(a));
        } else {
            // Use Legendre's continued fraction for Q(a, x) = 1 - P(a, x)
            double b = x + 1.0 - a;
            double c = 1.0 / 1.0e-30;
            double d = 1.0 / b;
            double h = d;
            for (int i = 1; i <= 100; i++) {
                double an = -i * (i - a);
                b += 2.0;
                d = an * d + b;
                if (Math.abs(d) < 1.0e-30) d = 1.0e-30;
                c = b + an / c;
                if (Math.abs(c) < 1.0e-30) c = 1.0e-30;
                d = 1.0 / d;
                double del = d * c;
                h *= del;
                if (Math.abs(del - 1.0) < 1.0e-14) {
                    break;
                }
            }
            double q = Math.exp(-x + a * Math.log(x) - logGamma(a)) * h;
            return 1.0 - q;
        }
    }

    /**
     * Lanczos approximation for log(Gamma(x)).
     */
    public static double logGamma(double x) {
        double[] cof = {
                76.18009172947146,
                -86.50532032941677,
                24.01409824083091,
                -1.231739572450155,
                0.1208650973866179e-2,
                -0.5395239384953e-5
        };
        double y = x;
        double tmp = x + 5.5;
        tmp -= (x + 0.5) * Math.log(tmp);
        double ser = 1.000000000190015;
        for (int j = 0; j < 6; j++) {
            y += 1.0;
            ser += cof[j] / y;
        }
        return -tmp + Math.log(2.5066282746310005 * ser / x);
    }

    public double getChiSquareRed() {
        return chiSquareRed;
    }

    public double getChiSquareGreen() {
        return chiSquareGreen;
    }

    public double getChiSquareBlue() {
        return chiSquareBlue;
    }

    public double getpValueRed() {
        return pValueRed;
    }

    public double getpValueGreen() {
        return pValueGreen;
    }

    public double getpValueBlue() {
        return pValueBlue;
    }

    public double getOverallProbability() {
        return overallProbability;
    }

    public double getSuspicionScore() {
        return suspicionScore;
    }
}

