import java.awt.image.BufferedImage;

/**
 * ImageQualityMetrics provides objective visual quality evaluations
 * between a cover image and a stego-image:
 * <ul>
 *   <li><b>Mean Squared Error (MSE):</b> Average squared difference across all pixel color channels.</li>
 *   <li><b>Peak Signal-to-Noise Ratio (PSNR):</b> Ratio of maximum pixel intensity to distortion noise in decibels (dB).</li>
 *   <li><b>Structural Similarity Index (SSIM):</b> Evaluates visual quality by measuring luminance, contrast, and structure.</li>
 * </ul>
 */
public class ImageQualityMetrics {

    /**
     * Calculates Mean Squared Error (MSE) between two images.
     *
     * @param img1 Original cover image.
     * @param img2 Stego-image.
     * @return MSE value (0.0 indicates identical images).
     */
    public static double calculateMSE(BufferedImage img1, BufferedImage img2) {
        int width = img1.getWidth();
        int height = img1.getHeight();

        if (width != img2.getWidth() || height != img2.getHeight()) {
            throw new IllegalArgumentException("Images must have identical dimensions to compute MSE.");
        }

        double sumSquaredDiff = 0.0;
        int totalChannels = width * height * 3;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int rgb1 = img1.getRGB(x, y);
                int rgb2 = img2.getRGB(x, y);

                int r1 = (rgb1 >> 16) & 0xFF;
                int g1 = (rgb1 >> 8) & 0xFF;
                int b1 = rgb1 & 0xFF;

                int r2 = (rgb2 >> 16) & 0xFF;
                int g2 = (rgb2 >> 8) & 0xFF;
                int b2 = rgb2 & 0xFF;

                int diffR = r1 - r2;
                int diffG = g1 - g2;
                int diffB = b1 - b2;

                sumSquaredDiff += (diffR * diffR) + (diffG * diffG) + (diffB * diffB);
            }
        }

        return sumSquaredDiff / totalChannels;
    }

    /**
     * Calculates Peak Signal-to-Noise Ratio (PSNR) in decibels (dB).
     * Typical steganographic quality exceeds 40 dB (imperceptible to human eye).
     *
     * @param img1 Original cover image.
     * @param img2 Stego-image.
     * @return PSNR in dB (returns 100.0 dB if MSE is 0).
     */
    public static double calculatePSNR(BufferedImage img1, BufferedImage img2) {
        double mse = calculateMSE(img1, img2);
        if (mse == 0.0) {
            return 100.0; // Perceptually identical
        }
        return 10.0 * Math.log10((255.0 * 255.0) / mse);
    }

    /**
     * Calculates the Structural Similarity Index (SSIM) between two images.
     * Values range from -1 to +1 (1.0000 indicates perfect structural identity).
     *
     * @param img1 Original cover image.
     * @param img2 Stego-image.
     * @return SSIM index in range [-1.0, 1.0].
     */
    public static double calculateSSIM(BufferedImage img1, BufferedImage img2) {
        int width = img1.getWidth();
        int height = img1.getHeight();

        if (width != img2.getWidth() || height != img2.getHeight()) {
            throw new IllegalArgumentException("Images must have identical dimensions to compute SSIM.");
        }

        double c1 = Math.pow(0.01 * 255.0, 2);
        double c2 = Math.pow(0.03 * 255.0, 2);

        int totalPixels = width * height;

        // Compute means
        double mean1 = 0.0;
        double mean2 = 0.0;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                mean1 += getLuminance(img1.getRGB(x, y));
                mean2 += getLuminance(img2.getRGB(x, y));
            }
        }
        mean1 /= totalPixels;
        mean2 /= totalPixels;

        // Compute variances and covariance
        double var1 = 0.0;
        double var2 = 0.0;
        double covar = 0.0;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                double lum1 = getLuminance(img1.getRGB(x, y));
                double lum2 = getLuminance(img2.getRGB(x, y));

                double diff1 = lum1 - mean1;
                double diff2 = lum2 - mean2;

                var1 += diff1 * diff1;
                var2 += diff2 * diff2;
                covar += diff1 * diff2;
            }
        }

        var1 /= (totalPixels - 1);
        var2 /= (totalPixels - 1);
        covar /= (totalPixels - 1);

        double numerator = (2.0 * mean1 * mean2 + c1) * (2.0 * covar + c2);
        double denominator = (mean1 * mean1 + mean2 * mean2 + c1) * (var1 + var2 + c2);

        if (denominator == 0.0) {
            return 1.0;
        }

        return numerator / denominator;
    }

    private static double getLuminance(int rgb) {
        int r = (rgb >> 16) & 0xFF;
        int g = (rgb >> 8) & 0xFF;
        int b = rgb & 0xFF;
        return 0.299 * r + 0.587 * g + 0.114 * b;
    }
}

