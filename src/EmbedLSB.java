import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.awt.image.ColorModel;
import java.awt.image.WritableRaster;
import java.io.File;
import java.io.IOException;

/**
 * EmbedLSB implements spatial domain Least Significant Bit (LSB) image steganography.
 *
 * <p><b>Embedding Strategy:</b></p>
 * <ul>
 *   <li>Each ASCII character consists of 8 bits.</li>
 *   <li>Each character is embedded across <b>3 pixels</b> (9 color channels: R, G, B for each).</li>
 *   <li><b>Pixel 1:</b> R holds bit 0, G holds bit 1, B holds bit 2.</li>
 *   <li><b>Pixel 2:</b> R holds bit 3, G holds bit 4, B holds bit 5.</li>
 *   <li><b>Pixel 3:</b> R holds bit 6, G holds bit 7.
 *       The Blue (B) channel holds the <b>Termination Flag:</b>
 *       <ul>
 *         <li>{@code '1'} if more characters follow.</li>
 *         <li>{@code '0'} if this is the final character of the message.</li>
 *       </ul>
 *   </li>
 * </ul>
 * Lossless PNG format is strictly required to preserve the altered least significant bits.
 */
public class EmbedLSB {

    /**
     * Embeds an encrypted message payload into an image and saves the resulting stego-image.
     *
     * @param imageFile The source cover image file.
     * @param message The Base64-encoded encrypted payload to hide.
     * @param newImageFileString The file path destination for the new stego-image.
     * @throws IOException If image reading or writing fails.
     * @throws IllegalArgumentException If the image has insufficient pixel capacity for the payload.
     */
    public static void Embed(File imageFile, String message, String newImageFileString) throws IOException {
        if (imageFile == null) {
            throw new IllegalArgumentException("Source image file cannot be null.");
        }
        if (message == null || message.trim().isEmpty()) {
            throw new IllegalArgumentException("Message to embed cannot be null or empty.");
        }
        if (newImageFileString == null || newImageFileString.trim().isEmpty()) {
            throw new IllegalArgumentException("Output image path cannot be null or empty.");
        }
        if (!imageFile.exists()) {
            throw new IOException("Source image file not found: " + imageFile.getAbsolutePath());
        }

        BufferedImage originalImage = ImageIO.read(imageFile);
        if (originalImage == null) {
            throw new IOException("Failed to load source image (unsupported or corrupted format): " + imageFile.getName());
        }

        BufferedImage stegoImage = embedToBufferedImage(originalImage, message);

        // Write stego-image to disk as lossless PNG
        File newImageFile = new File(newImageFileString);
        File parentDir = newImageFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }
        SaveNewFile(stegoImage, newImageFile);
    }

    /**
     * Embeds the message payload directly into a clone of the BufferedImage, returning the stego image.
     *
     * @param originalImage The cover image.
     * @param message The Base64 encrypted payload.
     * @return New BufferedImage containing the steganographic data.
     */
    public static BufferedImage embedToBufferedImage(BufferedImage originalImage, String message) {
        if (originalImage == null) {
            throw new IllegalArgumentException("Cover image cannot be null.");
        }
        if (message == null || message.trim().isEmpty()) {
            throw new IllegalArgumentException("Message to embed cannot be null or empty.");
        }

        BufferedImage stegoImage = GetImage(originalImage);
        Pixel[] pixels = GetPixelArray(stegoImage);
        String[] messageInBinary = ConvertMessageToBinary(message);

        // Validation: Verify image capacity
        int requiredPixels = messageInBinary.length * 3;
        if (pixels.length < requiredPixels) {
            throw new IllegalArgumentException(String.format(
                    "Image capacity exceeded! Image contains %d pixels (max %d characters), but payload requires %d pixels (%d characters).",
                    pixels.length, pixels.length / 3, requiredPixels, messageInBinary.length
            ));
        }

        // Embed the binary message into pixel LSBs
        EncodeMessageBinaryInPixels(pixels, messageInBinary);

        // Apply modified pixels to the new buffered image (only update altered pixels for speed)
        ReplacePixelsInNewBufferedImage(pixels, stegoImage, requiredPixels);
        return stegoImage;
    }

    private static BufferedImage GetImage(BufferedImage image) {
        ColorModel colorModel = image.getColorModel();
        boolean isAlphaPremultiplied = colorModel.isAlphaPremultiplied();
        WritableRaster raster = image.copyData(null);
        return new BufferedImage(colorModel, raster, isAlphaPremultiplied, null);
    }

    private static Pixel[] GetPixelArray(BufferedImage bufferedImage) {
        int height = bufferedImage.getHeight();
        int width = bufferedImage.getWidth();
        Pixel[] pixels = new Pixel[height * width];
        int count = 0;
        // Scans column-by-column (column-major)
        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                Color colorToAdd = new Color(bufferedImage.getRGB(x, y));
                pixels[count] = new Pixel(x, y, colorToAdd);
                count++;
            }
        }
        return pixels;
    }

    private static String[] ConvertMessageToBinary(String message) {
        int[] messageInAscii = ConvertMessageToAscii(message);
        return ConvertAsciiToBinary(messageInAscii);
    }

    private static int[] ConvertMessageToAscii(String message) {
        int[] messageCharactersInAscii = new int[message.length()];
        for (int i = 0; i < message.length(); i++) {
            messageCharactersInAscii[i] = (int) message.charAt(i);
        }
        return messageCharactersInAscii;
    }

    private static String[] ConvertAsciiToBinary(int[] messageInAscii) {
        String[] messageInBinary = new String[messageInAscii.length];
        for (int i = 0; i < messageInAscii.length; i++) {
            String asciiBinary = LeftPadZeros(Integer.toBinaryString(messageInAscii[i]));
            messageInBinary[i] = asciiBinary;
        }
        return messageInBinary;
    }

    /**
     * Pads a binary string to 8 bits by prepending zeros.
     */
    private static String LeftPadZeros(String value) {
        StringBuilder paddedValue = new StringBuilder("00000000");
        int offSet = 8 - value.length();
        if (offSet < 0) {
            offSet = 0;
        }
        for (int i = 0; i < value.length(); i++) {
            paddedValue.setCharAt(i + offSet, value.charAt(i));
        }
        return paddedValue.toString();
    }

    /**
     * Embeds each 8-bit character into a 3-pixel block.
     */
    private static void EncodeMessageBinaryInPixels(Pixel[] pixels, String[] messageBinary) {
        int pixelIndex = 0;
        boolean isLastCharacter = false;
        for (int i = 0; i < messageBinary.length; i++) {
            Pixel[] currentPixels = new Pixel[]{pixels[pixelIndex], pixels[pixelIndex + 1], pixels[pixelIndex + 2]};
            if (i + 1 == messageBinary.length) {
                isLastCharacter = true;
            }
            ChangePixelsColor(messageBinary[i], currentPixels, isLastCharacter);
            pixelIndex += 3;
        }
    }

    /**
     * Alters RGB components using LSB substitution.
     * Pixels 0 & 1 take 3 bits each (6 bits total).
     * Pixel 2 takes 2 bits (bits 6 and 7) and sets the Blue channel to '0' (last) or '1' (continue).
     */
    private static void ChangePixelsColor(String messageBinary, Pixel[] pixels, boolean isLastCharacter) {
        int messageBinaryIndex = 0;
        for (int i = 0; i < pixels.length - 1; i++) {
            char[] messageBinaryChars = new char[]{
                    messageBinary.charAt(messageBinaryIndex),
                    messageBinary.charAt(messageBinaryIndex + 1),
                    messageBinary.charAt(messageBinaryIndex + 2)
            };
            String[] pixelRGBBinary = GetPixelsRGBBinary(pixels[i], messageBinaryChars);
            pixels[i].setColor(GetNewPixelColor(pixelRGBBinary));
            messageBinaryIndex += 3;
        }

        // For the 3rd pixel: R = bit 6, G = bit 7, B = stop/continue bit
        char stopBit = isLastCharacter ? '0' : '1';
        char[] messageBinaryChars = new char[]{
                messageBinary.charAt(messageBinaryIndex),
                messageBinary.charAt(messageBinaryIndex + 1),
                stopBit
        };
        String[] pixelRGBBinary = GetPixelsRGBBinary(pixels[pixels.length - 1], messageBinaryChars);
        pixels[pixels.length - 1].setColor(GetNewPixelColor(pixelRGBBinary));
    }

    private static String[] GetPixelsRGBBinary(Pixel pixel, char[] messageBinaryChars) {
        String[] pixelRGBBinary = new String[3];
        pixelRGBBinary[0] = ChangePixelBinary(Integer.toBinaryString(pixel.getColor().getRed()), messageBinaryChars[0]);
        pixelRGBBinary[1] = ChangePixelBinary(Integer.toBinaryString(pixel.getColor().getGreen()), messageBinaryChars[1]);
        pixelRGBBinary[2] = ChangePixelBinary(Integer.toBinaryString(pixel.getColor().getBlue()), messageBinaryChars[2]);
        return pixelRGBBinary;
    }

    private static String ChangePixelBinary(String pixelBinary, char messageBinaryChar) {
        StringBuilder sb = new StringBuilder(pixelBinary);
        sb.setCharAt(pixelBinary.length() - 1, messageBinaryChar);
        return sb.toString();
    }

    private static Color GetNewPixelColor(String[] colorBinary) {
        return new Color(
                Integer.parseInt(colorBinary[0], 2),
                Integer.parseInt(colorBinary[1], 2),
                Integer.parseInt(colorBinary[2], 2)
        );
    }

    private static void ReplacePixelsInNewBufferedImage(Pixel[] newPixels, BufferedImage newImage, int modifiedPixelCount) {
        int limit = Math.min(newPixels.length, modifiedPixelCount);
        for (int i = 0; i < limit; i++) {
            Pixel pixel = newPixels[i];
            newImage.setRGB(pixel.getX(), pixel.getY(), pixel.getColor().getRGB());
        }
    }

    private static void SaveNewFile(BufferedImage newImage, File newImageFile) throws IOException {
        boolean success = ImageIO.write(newImage, "png", newImageFile);
        if (!success) {
            throw new IOException("No appropriate image writer found for PNG format.");
        }
    }
}
