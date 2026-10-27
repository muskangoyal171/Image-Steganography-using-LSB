import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

/**
 * ExtractLSB extracts hidden messages from an image that was encoded using
 * spatial domain Least Significant Bit (LSB) steganography.
 *
 * <p><b>Extraction Process:</b></p>
 * <ol>
 *   <li>Traverses image pixels in the identical column-major order as {@link EmbedLSB}.</li>
 *   <li>Extracts groups of 3 pixels (9 color channels).</li>
 *   <li>Collects the LSB of the first 8 channels ($R_1, G_1, B_1, R_2, G_2, B_2, R_3, G_3$)
 *       to reconstruct the 8-bit ASCII character.</li>
 *   <li>Inspects the 9th channel ($B_3$ LSB) to check if the end-of-message flag is reached ('0').</li>
 *   <li>Reassembles the complete Base64 ciphertext payload.</li>
 *   <li>Passes the payload and user password to {@link TextDecryptor} for authenticated decryption.</li>
 * </ol>
 */
public class ExtractLSB {

    /**
     * Extracts and decrypts the secret message from the specified stego-image.
     *
     * @param newImageFileString Path to the stego-image file.
     * @param password Password for PBKDF2 key derivation and AES-GCM decryption.
     * @return The original decrypted plaintext message.
     * @throws SecurityException If tampering is detected or password is invalid.
     * @throws Exception If file reading, extraction, or decryption fails.
     */
    public static String Extract(String newImageFileString, String password) throws Exception {
        if (newImageFileString == null || newImageFileString.trim().isEmpty()) {
            throw new IllegalArgumentException("Stego image path cannot be null or empty.");
        }
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }

        File newImageFile = new File(newImageFileString);
        if (!newImageFile.exists()) {
            throw new IOException("Steganographic image not found: " + newImageFileString);
        }

        BufferedImage image = ImageIO.read(newImageFile);
        if (image == null) {
            throw new IOException("Failed to parse image (unsupported or corrupted format): " + newImageFileString);
        }

        return extractFromBufferedImage(image, password);
    }

    /**
     * Extracts and decrypts secret message directly from a BufferedImage instance.
     *
     * @param image The stego-image.
     * @param password Decryption password.
     * @return Decrypted plaintext message.
     * @throws Exception If extraction, verification, or decryption fails.
     */
    public static String extractFromBufferedImage(BufferedImage image, String password) throws Exception {
        if (image == null) {
            throw new IllegalArgumentException("Stego image cannot be null.");
        }
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }

        Pixel[] pixels = GetPixelArray(image);
        String extractedPayload = ExtractMessageFromPixels(pixels);

        if (extractedPayload.isEmpty()) {
            throw new SecurityException("No hidden message detected or steganographic markers were corrupted.");
        }

        TextDecryptor textDecryptor = new TextDecryptor();
        return textDecryptor.decrypt(extractedPayload, password);
    }

    private static Pixel[] GetPixelArray(BufferedImage bufferedImage) {
        int height = bufferedImage.getHeight();
        int width = bufferedImage.getWidth();
        Pixel[] pixels = new Pixel[height * width];

        int count = 0;
        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                Color colorToAdd = new Color(bufferedImage.getRGB(x, y));
                pixels[count] = new Pixel(x, y, colorToAdd);
                count++;
            }
        }
        return pixels;
    }

    /**
     * Reads pixels in 3-pixel increments until the stop bit marker is reached.
     */
    private static String ExtractMessageFromPixels(Pixel[] pixels) {
        boolean completed = false;
        int pixelArrayIndex = 0;
        StringBuilder messageBuilder = new StringBuilder();

        while (!completed) {
            // Guard against running out of pixels on non-stego images or corrupted files
            if (pixelArrayIndex + 3 > pixels.length) {
                break;
            }

            Pixel[] pixelsToRead = new Pixel[3];
            for (int i = 0; i < 3; i++) {
                pixelsToRead[i] = pixels[pixelArrayIndex];
                pixelArrayIndex++;
            }

            messageBuilder.append(ConvertPixelsToCharacter(pixelsToRead));

            if (IsEndOfMessage(pixelsToRead[2])) {
                completed = true;
            }
        }

        // If completed is false, image ended without finding the end-of-message bit
        if (!completed) {
            return "";
        }

        return messageBuilder.toString();
    }

    /**
     * Converts a 3-pixel block (8 data bits + 1 control bit) into a single character.
     */
    private static char ConvertPixelsToCharacter(Pixel[] pixelsToRead) {
        ArrayList<String> binaryValues = new ArrayList<>();
        for (Pixel pixel : pixelsToRead) {
            String[] currentBinary = TurnPixelIntegersToBinary(pixel);
            binaryValues.add(currentBinary[0]); // Red
            binaryValues.add(currentBinary[1]); // Green
            binaryValues.add(currentBinary[2]); // Blue
        }
        return ConvertBinaryValuesToCharacter(binaryValues);
    }

    private static String[] TurnPixelIntegersToBinary(Pixel pixel) {
        String[] values = new String[3];
        values[0] = Integer.toBinaryString(pixel.getColor().getRed());
        values[1] = Integer.toBinaryString(pixel.getColor().getGreen());
        values[2] = Integer.toBinaryString(pixel.getColor().getBlue());
        return values;
    }

    /**
     * Checks the LSB of the 3rd pixel's Blue channel:
     * '0' indicates the last character of the message (End of Message).
     * '1' indicates more characters follow.
     */
    private static boolean IsEndOfMessage(Pixel pixel) {
        // Bitwise check on the Blue component's LSB
        return (pixel.getColor().getBlue() & 1) == 0;
    }

    /**
     * Takes the LSB of each of the first 8 color channels and parses them as an 8-bit character.
     */
    private static char ConvertBinaryValuesToCharacter(ArrayList<String> binaryValues) {
        StringBuilder endBinary = new StringBuilder();
        // Read first 8 bits (indices 0 through 7)
        for (int i = 0; i < 8; i++) {
            String colorBinary = binaryValues.get(i);
            endBinary.append(colorBinary.charAt(colorBinary.length() - 1));
        }
        int ascii = Integer.parseInt(endBinary.toString(), 2);
        return (char) ascii;
    }
}
