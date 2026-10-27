import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

/**
 * Steganalyzer is the main coordinator class for executing steganalytic evaluations
 * on digital images.
 *
 * <p>It orchestrates four distinct forensic techniques:</p>
 * <ol>
 *   <li><b>LSB Statistical Analysis:</b> Bit distribution, Shannon entropy, spatial autocorrelation, runs test.</li>
 *   <li><b>Chi-Square PoV Analysis:</b> Westfeld & Pfitzmann Pairs-of-Values equalized distribution attack.</li>
 *   <li><b>RS Steganalysis:</b> Fridrich et al. Regular/Singular group smoothness analysis and payload estimation.</li>
 *   <li><b>DCT Coefficient Analysis:</b> 2D block DCT, Benford's Law compliance, high-frequency energy, blockiness.</li>
 * </ol>
 */
public class Steganalyzer {

    /**
     * Executes all four steganalysis techniques on the specified image file.
     *
     * @param imagePath Path to the target image file.
     * @return Complete SteganalysisReport containing all individual and ensemble scores.
     * @throws IOException If image file does not exist or format is unsupported.
     */
    public static SteganalysisReport analyze(String imagePath) throws IOException {
        File file = new File(imagePath);
        if (!file.exists()) {
            throw new IOException("Target image file not found: " + imagePath);
        }

        BufferedImage image = ImageIO.read(file);
        if (image == null) {
            throw new IOException("Failed to load image (unsupported or corrupted file format): " + imagePath);
        }

        return analyze(image, imagePath);
    }

    /**
     * Executes steganalysis directly on a BufferedImage instance.
     *
     * @param image The loaded BufferedImage.
     * @param sourcePath A descriptive path or name for reporting.
     * @return Complete SteganalysisReport.
     */
    public static SteganalysisReport analyze(BufferedImage image, String sourcePath) {
        // Run all four analyses
        LsbAnalysis lsb = LsbAnalysis.analyze(image);
        ChiSquareAnalysis chiSq = ChiSquareAnalysis.analyze(image);
        RSAnalysis rs = RSAnalysis.analyze(image);
        DctAnalysis dct = DctAnalysis.analyze(image);

        return new SteganalysisReport(sourcePath, image.getWidth(), image.getHeight(), lsb, chiSq, rs, dct);
    }
}

