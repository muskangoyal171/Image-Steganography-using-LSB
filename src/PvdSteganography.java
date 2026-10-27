import java.awt.image.BufferedImage;
import java.awt.image.ColorModel;
import java.awt.image.WritableRaster;

/**
 * PvdSteganography implements the Pixel Value Differencing (PVD) steganography
 * algorithm originally introduced by Da-Chun Wu and Wen-Hsiang Tsai (2003).
 *
 * <p><b>PVD Concept & Range Table:</b></p>
 * <ul>
 *   <li>The Human Visual System (HVS) is sensitive to changes in smooth regions, but
 *       relatively tolerant of variations in high-contrast edge regions.</li>
 *   <li>PVD divides the image into non-overlapping consecutive pixel pairs \((p_0, p_1)\).</li>
 *   <li>The difference \(d = |p_0 - p_1|\) determines how many bits can be embedded:
 *       smooth areas (low \(d\)) embed fewer bits (e.g. 3 bits), while edge areas
 *       (high \(d\)) embed more bits (up to 7 bits) without visible artifacts.</li>
 *   <li><b>Standard Range Table:</b>
 *       <ul>
 *         <li>\(R_1 = [0, 7]\): width 8 \(\implies 3\) bits</li>
 *         <li>\(R_2 = [8, 15]\): width 8 \(\implies 3\) bits</li>
 *         <li>\(R_3 = [16, 31]\): width 16 \(\implies 4\) bits</li>
 *         <li>\(R_4 = [32, 63]\): width 32 \(\implies 5\) bits</li>
 *         <li>\(R_5 = [64, 127]\): width 64 \(\implies 6\) bits</li>
 *         <li>\(R_6 = [128, 255]\): width 128 \(\implies 7\) bits</li>
 *       </ul>
 *   </li>
 * </ul>
 */
public class PvdSteganography {

    // Range bounds [lower, upper]
    public static final int[][] RANGES = {
            {0, 7},
            {8, 15},
            {16, 31},
            {32, 63},
            {64, 127},
            {128, 255}
    };

    /**
     * Calculates the maximum bit capacity of the image using PVD.
     *
     * @param image Cover image.
     * @return Maximum embeddable bits.
     */
    public static int calculateCapacityBits(BufferedImage image) {
        int width = image.getWidth();
        int height = image.getHeight();
        int totalCapacity = 0;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width - 1; x += 2) {
                int rgb1 = image.getRGB(x, y);
                int rgb2 = image.getRGB(x + 1, y);

                for (int c = 0; c < 3; c++) {
                    int p0 = (rgb1 >> (c * 8)) & 0xFF;
                    int p1 = (rgb2 >> (c * 8)) & 0xFF;
                    int d = Math.abs(p0 - p1);
                    int rangeIndex = getRangeIndex(d);
                    int capacityBits = getBitsForRange(rangeIndex);
                    totalCapacity += capacityBits;
                }
            }
        }
        // Deduct 32 bits for the length header
        return Math.max(0, totalCapacity - 32);
    }

    /**
     * Embeds a string payload into the cover image using PVD.
     *
     * @param coverImage The original image.
     * @param payload The secret text / ciphertext payload to embed.
     * @return New BufferedImage containing the steganographic data.
     */
    public static BufferedImage embed(BufferedImage coverImage, String payload) {
        if (coverImage == null) {
            throw new IllegalArgumentException("Cover image cannot be null.");
        }
        if (payload == null || payload.trim().isEmpty()) {
            throw new IllegalArgumentException("Payload cannot be null or empty.");
        }

        BufferedImage stegoImage = cloneImage(coverImage);
        int width = stegoImage.getWidth();
        int height = stegoImage.getHeight();

        // Convert payload to binary string
        StringBuilder bitStream = new StringBuilder();

        // 32-bit header containing payload character count
        String lengthHeader = String.format("%32s", Integer.toBinaryString(payload.length())).replace(' ', '0');
        bitStream.append(lengthHeader);

        for (int i = 0; i < payload.length(); i++) {
            String charBits = String.format("%8s", Integer.toBinaryString(payload.charAt(i))).replace(' ', '0');
            bitStream.append(charBits);
        }

        int totalBitsToEmbed = bitStream.length();
        int bitIndex = 0;

        for (int y = 0; y < height && bitIndex < totalBitsToEmbed; y++) {
            for (int x = 0; x < width - 1 && bitIndex < totalBitsToEmbed; x += 2) {
                int rgb1 = stegoImage.getRGB(x, y);
                int rgb2 = stegoImage.getRGB(x + 1, y);

                int[] newP0 = new int[3];
                int[] newP1 = new int[3];

                for (int c = 0; c < 3; c++) {
                    int p0 = (rgb1 >> (c * 8)) & 0xFF;
                    int p1 = (rgb2 >> (c * 8)) & 0xFF;

                    if (bitIndex < totalBitsToEmbed) {
                        int d = Math.abs(p0 - p1);
                        int rangeIndex = getRangeIndex(d);
                        int bitsToEmbed = getBitsForRange(rangeIndex);

                        // Take up to bitsToEmbed
                        int remaining = totalBitsToEmbed - bitIndex;
                        int currentEmbedBits = Math.min(bitsToEmbed, remaining);

                        String subBits = bitStream.substring(bitIndex, bitIndex + currentEmbedBits);
                        // If remaining was less than range capacity, pad with 0s
                        while (subBits.length() < bitsToEmbed) {
                            subBits += "0";
                        }
                        int b = Integer.parseInt(subBits, 2);
                        bitIndex += currentEmbedBits;

                        // Calculate new difference d'
                        int lower = RANGES[rangeIndex][0];
                        int dPrime = lower + b;
                        int m = Math.abs(dPrime - d);

                        int p0Prime, p1Prime;
                        if (p0 >= p1) {
                            if (dPrime > d) {
                                p0Prime = p0 + (int) Math.ceil(m / 2.0);
                                p1Prime = p1 - (int) Math.floor(m / 2.0);
                            } else {
                                p0Prime = p0 - (int) Math.ceil(m / 2.0);
                                p1Prime = p1 + (int) Math.floor(m / 2.0);
                            }
                        } else {
                            if (dPrime > d) {
                                p0Prime = p0 - (int) Math.floor(m / 2.0);
                                p1Prime = p1 + (int) Math.ceil(m / 2.0);
                            } else {
                                p0Prime = p0 + (int) Math.floor(m / 2.0);
                                p1Prime = p1 - (int) Math.ceil(m / 2.0);
                            }
                        }

                        // Boundary handling to maintain |p0Prime - p1Prime| == dPrime in [0, 255]
                        if (p0Prime < 0) {
                            p0Prime = 0;
                            p1Prime = dPrime;
                        } else if (p1Prime < 0) {
                            p1Prime = 0;
                            p0Prime = dPrime;
                        } else if (p0Prime > 255) {
                            p0Prime = 255;
                            p1Prime = 255 - dPrime;
                        } else if (p1Prime > 255) {
                            p1Prime = 255;
                            p0Prime = 255 - dPrime;
                        }

                        newP0[c] = Math.max(0, Math.min(255, p0Prime));
                        newP1[c] = Math.max(0, Math.min(255, p1Prime));
                    } else {
                        newP0[c] = p0;
                        newP1[c] = p1;
                    }
                }

                int newRgb1 = (newP0[2] << 16) | (newP0[1] << 8) | newP0[0];
                int newRgb2 = (newP1[2] << 16) | (newP1[1] << 8) | newP1[0];

                stegoImage.setRGB(x, y, newRgb1);
                stegoImage.setRGB(x + 1, y, newRgb2);
            }
        }

        if (bitIndex < totalBitsToEmbed) {
            throw new IllegalArgumentException("Payload size exceeds PVD capacity of the image.");
        }

        return stegoImage;
    }

    /**
     * Extracts a secret payload embedded via PVD.
     *
     * @param stegoImage The steganographic image.
     * @return Extracted string message.
     */
    public static String extract(BufferedImage stegoImage) {
        if (stegoImage == null) {
            throw new IllegalArgumentException("Stego image cannot be null.");
        }

        int width = stegoImage.getWidth();
        int height = stegoImage.getHeight();

        StringBuilder extractedBits = new StringBuilder();
        int targetPayloadChars = -1;
        int targetBits = -1;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width - 1; x += 2) {
                int rgb1 = stegoImage.getRGB(x, y);
                int rgb2 = stegoImage.getRGB(x + 1, y);

                for (int c = 0; c < 3; c++) {
                    int p0 = (rgb1 >> (c * 8)) & 0xFF;
                    int p1 = (rgb2 >> (c * 8)) & 0xFF;

                    int d = Math.abs(p0 - p1);
                    int rangeIndex = getRangeIndex(d);
                    int bitsToRead = getBitsForRange(rangeIndex);

                    int lower = RANGES[rangeIndex][0];
                    int b = d - lower;

                    String binaryChunk = String.format("%" + bitsToRead + "s", Integer.toBinaryString(b)).replace(' ', '0');
                    extractedBits.append(binaryChunk);

                    // Check if 32-bit header is available
                    if (targetPayloadChars == -1 && extractedBits.length() >= 32) {
                        String headerBits = extractedBits.substring(0, 32);
                        targetPayloadChars = Integer.parseInt(headerBits, 2);
                        if (targetPayloadChars <= 0 || targetPayloadChars > width * height) {
                            return ""; // Invalid header or not a PVD stego-image
                        }
                        targetBits = 32 + (targetPayloadChars * 8);
                    }

                    if (targetBits != -1 && extractedBits.length() >= targetBits) {
                        break;
                    }
                }
                if (targetBits != -1 && extractedBits.length() >= targetBits) {
                    break;
                }
            }
            if (targetBits != -1 && extractedBits.length() >= targetBits) {
                break;
            }
        }

        if (targetPayloadChars <= 0 || extractedBits.length() < targetBits) {
            return "";
        }

        // Parse payload characters
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < targetPayloadChars; i++) {
            int start = 32 + (i * 8);
            String charBits = extractedBits.substring(start, start + 8);
            int ascii = Integer.parseInt(charBits, 2);
            result.append((char) ascii);
        }

        return result.toString();
    }

    private static int getRangeIndex(int diff) {
        for (int i = 0; i < RANGES.length; i++) {
            if (diff >= RANGES[i][0] && diff <= RANGES[i][1]) {
                return i;
            }
        }
        return RANGES.length - 1;
    }

    private static int getBitsForRange(int rangeIndex) {
        int width = RANGES[rangeIndex][1] - RANGES[rangeIndex][0] + 1;
        return (int) (Math.log(width) / Math.log(2));
    }

    private static BufferedImage cloneImage(BufferedImage img) {
        ColorModel cm = img.getColorModel();
        boolean isAlphaPremultiplied = cm.isAlphaPremultiplied();
        WritableRaster raster = img.copyData(null);
        return new BufferedImage(cm, raster, isAlphaPremultiplied, null);
    }
}

