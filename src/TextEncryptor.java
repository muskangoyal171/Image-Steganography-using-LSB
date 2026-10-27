import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * TextEncryptor handles password-based key derivation and authenticated encryption
 * using AES-256 in Galois/Counter Mode (GCM).
 *
 * <p><b>Security Features:</b></p>
 * <ul>
 *   <li><b>Password-Based Key Derivation (PBKDF2):</b> Uses PBKDF2WithHmacSHA256 with 65,536 iterations
 *       and a cryptographically secure 128-bit random salt to mitigate dictionary and rainbow-table attacks.</li>
 *   <li><b>AES-256-GCM Authenticated Encryption:</b> Uses AES in GCM mode (Galois/Counter Mode),
 *       providing both confidentiality and integrity/authenticity (AEAD).</li>
 *   <li><b>Unique Initialization Vector (IV):</b> Generates a fresh 96-bit (12-byte) random IV per encryption,
 *       preventing replay and pattern analysis attacks.</li>
 *   <li><b>Integrated Authentication Tag:</b> Generates a 128-bit GMAC authentication tag appended to the ciphertext,
 *       allowing detection of any tampering or bit modification during decryption.</li>
 *   <li><b>Payload Packaging:</b> Packages [16-byte Salt || 12-byte IV || Ciphertext + 16-byte Tag]
 *       and encodes it in Base64 for safe ASCII embedding into image pixels.</li>
 * </ul>
 */
public class TextEncryptor {

    // Cryptographic configuration constants
    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";

    public static final int SALT_LENGTH_BYTE = 16;  // 128 bits
    public static final int IV_LENGTH_BYTE = 12;    // 96 bits (standard recommended for GCM)
    public static final int TAG_LENGTH_BIT = 128;   // 128 bits authentication tag
    public static final int ITERATION_COUNT = 65536; // OWASP recommended minimum for PBKDF2
    public static final int KEY_LENGTH_BIT = 256;   // 256-bit AES key

    private final SecureRandom secureRandom;

    public TextEncryptor() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Derives a 256-bit AES SecretKey from a user-supplied password and random salt
     * using the PBKDF2WithHmacSHA256 key derivation function.
     *
     * @param password The user-supplied passphrase.
     * @param salt The 16-byte random salt.
     * @return A 256-bit AES SecretKey.
     * @throws NoSuchAlgorithmException If PBKDF2WithHmacSHA256 is not available.
     * @throws InvalidKeySpecException If key specification is invalid.
     */
    public static SecretKey deriveKeyFromPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH_BIT);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Encrypts the plaintext message using AES-256-GCM with a key derived from the password.
     *
     * <p>Structure of generated binary payload:
     * <pre>
     * +-------------------+------------------+------------------------------------+
     * |  Salt (16 bytes)  |   IV (12 bytes)  |  Ciphertext + Auth Tag (16 bytes)  |
     * +-------------------+------------------+------------------------------------+
     * </pre>
     * The combined binary payload is Base64 encoded before being returned.
     *
     * @param plaintext The secret message to encrypt.
     * @param password The password used to derive the encryption key.
     * @return Base64-encoded string representing [Salt || IV || Ciphertext+Tag].
     * @throws Exception If encryption fails.
     */
    public String encrypt(String plaintext, String password) throws Exception {
        if (plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("Message to encrypt cannot be null or empty.");
        }
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }

        // Step 1: Generate a cryptographically secure 128-bit (16-byte) random salt
        byte[] salt = new byte[SALT_LENGTH_BYTE];
        secureRandom.nextBytes(salt);

        // Step 2: Derive 256-bit AES SecretKey via PBKDF2-HMAC-SHA256
        SecretKey secretKey = deriveKeyFromPassword(password, salt);

        // Step 3: Generate a cryptographically secure 96-bit (12-byte) random IV for GCM
        byte[] iv = new byte[IV_LENGTH_BYTE];
        secureRandom.nextBytes(iv);

        // Step 4: Initialize AES/GCM/NoPadding Cipher
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        // Step 5: Encrypt plaintext bytes (GCM automatically appends the 128-bit authentication tag)
        byte[] inputBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] cipherTextWithTag = cipher.doFinal(inputBytes);

        // Step 6: Package Salt + IV + Ciphertext (with tag) into a single byte array
        ByteBuffer byteBuffer = ByteBuffer.allocate(salt.length + iv.length + cipherTextWithTag.length);
        byteBuffer.put(salt);
        byteBuffer.put(iv);
        byteBuffer.put(cipherTextWithTag);
        byte[] combinedPayload = byteBuffer.array();

        // Step 7: Encode to Base64 ASCII string so it can be cleanly converted to bits for LSB
        return Base64.getEncoder().encodeToString(combinedPayload);
    }
}
