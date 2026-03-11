package template.detection.smartdiff;

/**
 * Result of SmartDiff comparison between two responses.
 * Holds separate Jaccard similarity scores for content and structure.
 */
public class SmartDiffResult {

    private final double contentSimilarity;
    private final double structureSimilarity;

    public SmartDiffResult(double contentSimilarity, double structureSimilarity) {
        this.contentSimilarity = contentSimilarity;
        this.structureSimilarity = structureSimilarity;
    }

    public double getContentSimilarity() {
        return contentSimilarity;
    }

    public double getStructureSimilarity() {
        return structureSimilarity;
    }

    /**
     * Responses are "similar" if BOTH metrics are at or above their thresholds.
     */
    public boolean isSimilar(double contentThreshold, double structureThreshold) {
        return contentSimilarity >= contentThreshold && structureSimilarity >= structureThreshold;
    }

    /**
     * Responses "differ" if at least one metric is below its threshold.
     */
    public boolean isDifferent(double contentThreshold, double structureThreshold) {
        return !isSimilar(contentThreshold, structureThreshold);
    }

    @Override
    public String toString() {
        return String.format("SmartDiffResult[content=%.4f, structure=%.4f]",
                contentSimilarity, structureSimilarity);
    }
}
