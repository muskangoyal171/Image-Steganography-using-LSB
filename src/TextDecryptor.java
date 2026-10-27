import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * TextDecryptor handles Base64 payload decoding, password-based key derivation,
 * and authenticated decryption with integrity verification using AES-256-GCM.
 *
 * <p><b>Integrity Verification & Tamper Detection:</b></p>
 * <ul>
 *   <li>AES-GCM calculates a 128-bit Galois Message Authentication Code (GMAC) tag during encryption.</li>
 *   <li>During decryption, {@code cipher.doFinal()} verifies that the tag matches the ciphertext, IV, and key.</li>
 *   <li>If even a <i>single bit</i> of the hidden message is altered (or if an incorrect password is supplied),
 *       Java's cryptographic provider throws an {@link AEADBadTagException}.</li>
 *   <li>This class intercepts {@link AEADBadTagException} and signals an integrity verification failure.</li>
 * </ul>
 */
public class TextDecryptor {

    /**
     * Decrypts the Base64-encoded stego-payload using the supplied password,
     * verifying cryptographic integrity.
     *
     * @param base64CipherText The Base64 string extracted from the image pixels.
     * @param password The secret passphrase provided by the user.
     * @return The original decrypted plaintext message.
     * @throws SecurityException If integrity verification fails (tampering detected) or password is wrong.
     * @throws IllegalArgumentException If parameters or payload formats are invalid.
     * @throws Exception If decryption encounters unexpected cryptographic errors.
     */
    public String decrypt(String base64CipherText, String password) throws Exception {
        if (base64CipherText == null || base64CipherText.trim().isEmpty()) {
            throw new IllegalArgumentException("Ciphertext payload is empty or null.");
        }
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }

        // Step 1: Decode Base64 payload back to raw bytes
        byte[] combinedPayload;
        try {
            combinedPayload = Base64.getDecoder().decode(base64CipherText.trim());
        } catch (IllegalArgumentException e) {
            throw new SecurityException("Tampering detected: Extracted data is not valid Base64 format.", e);
        }

        // Step 2: Validate payload header minimum length
        int minHeaderLength = TextEncryptor.SALT_LENGTH_BYTE + TextEncryptor.IV_LENGTH_BYTE + (TextEncryptor.TAG_LENGTH_BIT / 8);
        if (combinedPayload.length < minHeaderLength) {
            throw new SecurityException("Tampering detected: Payload is incomplete (size: "
                    + combinedPayload.length + " bytes, minimum required: " + minHeaderLength + " bytes).");
        }

        ByteBuffer buffer = ByteBuffer.wrap(combinedPayload);

        // Step 3: Extract Salt (first 16 bytes)
        byte[] salt = new byte[TextEncryptor.SALT_LENGTH_BYTE];
        buffer.get(salt);

        // Step 4: Extract IV (subsequent 12 bytes)
        byte[] iv = new byte[TextEncryptor.IV_LENGTH_BYTE];
        buffer.get(iv);

        // Step 5: Extract Ciphertext + 128-bit Authentication Tag (remaining bytes)
        byte[] cipherTextWithTag = new byte[buffer.remaining()];
        buffer.get(cipherTextWithTag);

        // Step 6: Derive the 256-bit AES key using the extracted salt and provided password
        SecretKey secretKey = TextEncryptor.deriveKeyFromPassword(password, salt);

        // Step 7: Initialize AES-GCM Cipher in DECRYPT_MODE
        Cipher cipher = Cipher.getInstance(TextEncryptor.AES_GCM_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TextEncryptor.TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        // Step 8: Decrypt and verify GMAC authentication tag
        try {
            byte[] decryptedBytes = cipher.doFinal(cipherTextWithTag);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            // Cryptographic tag mismatch: indicates tampering or incorrect password
            throw new SecurityException(
                    "Integrity verification failed! The image data has been tampered with or the password is incorrect.",
                    e
            );
        }
    }
}
