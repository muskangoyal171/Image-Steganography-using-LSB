/**
 * ExperimentResult represents the quantitative findings from a single
 * experimental benchmark evaluation.
 */
public class ExperimentResult {

    private final String algorithm;
    private final int payloadPercentage;
    private final int payloadChars;
    private final int payloadBits;
    private final long embeddingTimeMs;
    private final long extractionTimeMs;
    private final long analysisTimeMs;
    private final boolean extractionSuccess;
    private final double mse;
    private final double psnr;
    private final double ssim;
    private final double lsbSuspicion;
    private final double chiSquareProb;
    private final double rsEstimatedPayload;
    private final double dctBenfordChiSq;
    private final double overallSuspicion;

    public ExperimentResult(String algorithm, int payloadPercentage, int payloadChars, int payloadBits,
                            long embeddingTimeMs, long extractionTimeMs, long analysisTimeMs,
                            boolean extractionSuccess, double mse, double psnr, double ssim,
                            double lsbSuspicion, double chiSquareProb, double rsEstimatedPayload,
                            double dctBenfordChiSq, double overallSuspicion) {
        this.algorithm = algorithm;
        this.payloadPercentage = payloadPercentage;
        this.payloadChars = payloadChars;
        this.payloadBits = payloadBits;
        this.embeddingTimeMs = embeddingTimeMs;
        this.extractionTimeMs = extractionTimeMs;
        this.analysisTimeMs = analysisTimeMs;
        this.extractionSuccess = extractionSuccess;
        this.mse = mse;
        this.psnr = psnr;
        this.ssim = ssim;
        this.lsbSuspicion = lsbSuspicion;
        this.chiSquareProb = chiSquareProb;
        this.rsEstimatedPayload = rsEstimatedPayload;
        this.dctBenfordChiSq = dctBenfordChiSq;
        this.overallSuspicion = overallSuspicion;
    }

    public static String getCsvHeader() {
        return "Algorithm,PayloadPercentage,PayloadChars,PayloadBits,EmbeddingTimeMs,ExtractionTimeMs," +
                "AnalysisTimeMs,ExtractionSuccess,MSE,PSNR_dB,SSIM,LsbSuspicion_Pct,ChiSquareProb_Pct," +
                "RsEstimatedPayload_Pct,DctBenfordChiSq,OverallSuspicion_Pct";
    }

    public String toCsvRow() {
        return String.format("%s,%d,%d,%d,%d,%d,%d,%b,%.4f,%.2f,%.4f,%.2f,%.2f,%.2f,%.2f,%.2f",
                algorithm, payloadPercentage, payloadChars, payloadBits,
                embeddingTimeMs, extractionTimeMs, analysisTimeMs, extractionSuccess,
                mse, psnr, ssim, lsbSuspicion, chiSquareProb, rsEstimatedPayload,
                dctBenfordChiSq, overallSuspicion);
    }

    public String getAlgorithm() { return algorithm; }
    public int getPayloadPercentage() { return payloadPercentage; }
    public int getPayloadChars() { return payloadChars; }
    public int getPayloadBits() { return payloadBits; }
    public long getEmbeddingTimeMs() { return embeddingTimeMs; }
    public long getExtractionTimeMs() { return extractionTimeMs; }
    public long getAnalysisTimeMs() { return analysisTimeMs; }
    public boolean isExtractionSuccess() { return extractionSuccess; }
    public double getMse() { return mse; }
    public double getPsnr() { return psnr; }
    public double getSsim() { return ssim; }
    public double getLsbSuspicion() { return lsbSuspicion; }
    public double getChiSquareProb() { return chiSquareProb; }
    public double getRsEstimatedPayload() { return rsEstimatedPayload; }
    public double getDctBenfordChiSq() { return dctBenfordChiSq; }
    public double getOverallSuspicion() { return overallSuspicion; }
}

