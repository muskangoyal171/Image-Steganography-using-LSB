/**
 * SteganalysisReport compiles and synthesizes findings from all four
 * steganalysis techniques: LSB Statistical, Chi-Square PoV, RS, and DCT Analysis.
 */
public class SteganalysisReport {

    private final String imagePath;
    private final int width;
    private final int height;

    private final LsbAnalysis lsbAnalysis;
    private final ChiSquareAnalysis chiSquareAnalysis;
    private final RSAnalysis rsAnalysis;
    private final DctAnalysis dctAnalysis;

    private final double overallSuspicionScore; // 0.0 to 100.0%
    private final String verdict;
    private final String confidenceLevel;

    public SteganalysisReport(String imagePath, int width, int height,
                              LsbAnalysis lsbAnalysis,
                              ChiSquareAnalysis chiSquareAnalysis,
                              RSAnalysis rsAnalysis,
                              DctAnalysis dctAnalysis) {
        this.imagePath = imagePath;
        this.width = width;
        this.height = height;
        this.lsbAnalysis = lsbAnalysis;
        this.chiSquareAnalysis = chiSquareAnalysis;
        this.rsAnalysis = rsAnalysis;
        this.dctAnalysis = dctAnalysis;

        // Weighted ensemble suspicion score
        // RS analysis has highest accuracy for spatial LSB (35%)
        // Chi-Square PoV is highly sensitive to bit equalization (30%)
        // LSB statistics assesses entropy & spatial correlation (20%)
        // DCT analysis detects frequency perturbations (15%)
        double combined = (rsAnalysis.getSuspicionScore() * 0.35)
                + (chiSquareAnalysis.getSuspicionScore() * 0.30)
                + (lsbAnalysis.getSuspicionScore() * 0.20)
                + (dctAnalysis.getSuspicionScore() * 0.15);

        this.overallSuspicionScore = Math.min(100.0, Math.max(0.0, combined));

        if (this.overallSuspicionScore >= 75.0) {
            this.verdict = "HIGH PROBABILITY OF STEGANOGRAPHY";
            this.confidenceLevel = "HIGH";
        } else if (this.overallSuspicionScore >= 50.0) {
            this.verdict = "SUSPICIOUS / PROBABLE EMBEDDED PAYLOAD";
            this.confidenceLevel = "MODERATE";
        } else if (this.overallSuspicionScore >= 25.0) {
            this.verdict = "LOW SUSPICION / UNLIKELY EMBEDDED";
            this.confidenceLevel = "LOW";
        } else {
            this.verdict = "CLEAN / NATURAL COVER IMAGE";
            this.confidenceLevel = "HIGH";
        }
    }

    /**
     * Formats the complete steganalysis findings into an ASCII report.
     */
    public String generateFormattedReport() {
        StringBuilder sb = new StringBuilder();

        sb.append("\n========================================================================================\n");
        sb.append("                          COMPREHENSIVE STEGANALYSIS REPORT                             \n");
        sb.append("========================================================================================\n");
        sb.append(String.format(" Image Path    : %s\n", imagePath));
        sb.append(String.format(" Dimensions    : %d x %d (%d pixels)\n", width, height, width * height));
        sb.append("----------------------------------------------------------------------------------------\n");
        sb.append(String.format(" OVERALL VERDICT       : %s\n", verdict));
        sb.append(String.format(" CONFIDENCE LEVEL      : %s\n", confidenceLevel));
        sb.append(String.format(" SUSPICION SCORE       : %s %.1f%%\n", renderBar(overallSuspicionScore), overallSuspicionScore));
        sb.append("========================================================================================\n\n");

        // 1. LSB Statistical Analysis
        sb.append("1. LSB STATISTICAL ANALYSIS\n");
        sb.append("----------------------------------------------------------------------------------------\n");
        sb.append(String.format("   • 0/1 Bit Ratio              : %.4f (Ones: %.2f%%, Zeros: %.2f%%)\n",
                lsbAnalysis.getBitOneRatio(), lsbAnalysis.getBitOneRatio() * 100, (1.0 - lsbAnalysis.getBitOneRatio()) * 100));
        sb.append(String.format("   • LSB Shannon Entropy        : %.4f / 1.0000 (Ideal Random = 1.0000)\n",
                lsbAnalysis.getEntropy()));
        sb.append(String.format("   • Horizontal Autocorrelation : %+.4f (Natural images > +0.10, Stego ~ 0.00)\n",
                lsbAnalysis.getHorizontalAutocorrelation()));
        sb.append(String.format("   • Vertical Autocorrelation   : %+.4f (Natural images > +0.10, Stego ~ 0.00)\n",
                lsbAnalysis.getVerticalAutocorrelation()));
        sb.append(String.format("   • Wald-Wolfowitz Z-Score     : %+.2f (Within [-1.96, +1.96] indicates random stream)\n",
                lsbAnalysis.getRunsZScore()));
        sb.append(String.format("   ► Test Suspicion Score       : %s %.1f%%\n\n",
                renderBar(lsbAnalysis.getSuspicionScore()), lsbAnalysis.getSuspicionScore()));

        // 2. Chi-Square PoV Analysis
        sb.append("2. CHI-SQUARE (PoV) ANALYSIS (Westfeld & Pfitzmann Attack)\n");
        sb.append("----------------------------------------------------------------------------------------\n");
        sb.append(String.format("   • Red Channel Chi-Square     : %.2f (Embedding Probability p = %.4f)\n",
                chiSquareAnalysis.getChiSquareRed(), chiSquareAnalysis.getpValueRed()));
        sb.append(String.format("   • Green Channel Chi-Square   : %.2f (Embedding Probability p = %.4f)\n",
                chiSquareAnalysis.getChiSquareGreen(), chiSquareAnalysis.getpValueGreen()));
        sb.append(String.format("   • Blue Channel Chi-Square    : %.2f (Embedding Probability p = %.4f)\n",
                chiSquareAnalysis.getChiSquareBlue(), chiSquareAnalysis.getpValueBlue()));
        sb.append(String.format("   • Combined PoV Probability   : %.2f%% (Values > 50%% suggest Pairs-of-Values equalization)\n",
                chiSquareAnalysis.getOverallProbability() * 100));
        sb.append(String.format("   ► Test Suspicion Score       : %s %.1f%%\n\n",
                renderBar(chiSquareAnalysis.getSuspicionScore()), chiSquareAnalysis.getSuspicionScore()));

        // 3. RS Analysis
        sb.append("3. RS (REGULAR / SINGULAR) STEGANALYSIS (Fridrich et al.)\n");
        sb.append("----------------------------------------------------------------------------------------\n");
        sb.append(String.format("   • R_M / S_M Group Ratios     : R_M = %.3f%%, S_M = %.3f%%\n",
                rsAnalysis.getrM() * 100, rsAnalysis.getsM() * 100));
        sb.append(String.format("   • R_-M / S_-M Group Ratios   : R_-M = %.3f%%, S_-M = %.3f%%\n",
                rsAnalysis.getrMinusM() * 100, rsAnalysis.getsMinusM() * 100));
        sb.append(String.format("   • Estimated Hidden Capacity  : %.2f%% of pixel capacity\n",
                rsAnalysis.getEstimatedPayloadRatio() * 100));
        sb.append(String.format("   ► Test Suspicion Score       : %s %.1f%%\n\n",
                renderBar(rsAnalysis.getSuspicionScore()), rsAnalysis.getSuspicionScore()));

        // 4. DCT Coefficient Analysis
        sb.append("4. DCT COEFFICIENT ANALYSIS (Frequency Domain & Benford's Law)\n");
        sb.append("----------------------------------------------------------------------------------------\n");
        sb.append(String.format("   • Benford's Law Chi-Square   : %.2f (p-value: %.4f, Natural images match Benford)\n",
                dctAnalysis.getBenfordChiSquare(), dctAnalysis.getBenfordPValue()));
        sb.append(String.format("   • High-Freq AC Energy Ratio  : %.2f%% (Elevated ratios indicate high-freq spatial noise)\n",
                dctAnalysis.getHighFrequencyEnergyRatio() * 100));
        sb.append(String.format("   • Blockiness Discontinuity   : %.3f (Deviation from 1.0 indicates grid-aligned artifacts)\n",
                dctAnalysis.getBlockinessMetric()));
        sb.append(String.format("   ► Test Suspicion Score       : %s %.1f%%\n",
                renderBar(dctAnalysis.getSuspicionScore()), dctAnalysis.getSuspicionScore()));

        sb.append("========================================================================================\n");
        return sb.toString();
    }

    private static String renderBar(double percentage) {
        int totalBlocks = 20;
        int filledBlocks = (int) Math.round((percentage / 100.0) * totalBlocks);
        filledBlocks = Math.max(0, Math.min(totalBlocks, filledBlocks));

        StringBuilder bar = new StringBuilder("[");
        for (int i = 0; i < filledBlocks; i++) {
            bar.append("█");
        }
        for (int i = filledBlocks; i < totalBlocks; i++) {
            bar.append("░");
        }
        bar.append("]");
        return bar.toString();
    }

    public double getOverallSuspicionScore() {
        return overallSuspicionScore;
    }

    public String getVerdict() {
        return verdict;
    }

    public String getConfidenceLevel() {
        return confidenceLevel;
    }

    public LsbAnalysis getLsbAnalysis() {
        return lsbAnalysis;
    }

    public ChiSquareAnalysis getChiSquareAnalysis() {
        return chiSquareAnalysis;
    }

    public RSAnalysis getRsAnalysis() {
        return rsAnalysis;
    }

    public DctAnalysis getDctAnalysis() {
        return dctAnalysis;
    }
}

