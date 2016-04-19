package security.sm;

import java.security.InvalidKeyException;
import java.security.Key;

/**
 * This abstract class represents the core of all block ciphers. It allows to
 * intialize the cipher and encrypt/decrypt single blocks. Larger quantities
 * are handled by modes, which are subclasses of FeedbackCipher.
 *
 * @see SMS4Crypt
 */
abstract class SymmetricCipher {

    SymmetricCipher() {
        // empty
    }

    /**
     * Retrieves this cipher's block size.
     *
     * @return the block size of this cipher
     */
    abstract int getBlockSize();

    /**
     * Initializes the cipher in the specified mode with the given key.
     *
     * @param decrypting flag indicating encryption or decryption
     * @param algorithm the algorithm name
     * @param key the key
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher
     */
    abstract void init(boolean decrypting, String algorithm, byte[] key)
        throws InvalidKeyException;

    /**
     * Encrypt one cipher block.
     *
     * <p>The input <code>plain</code>, starting at <code>plainOffset</code>
     * and ending at <code>(plainOffset+blockSize-1)</code>, is encrypted.
     * The result is stored in <code>cipher</code>, starting at
     * <code>cipherOffset</code>.
     *
     * @param plain the input buffer with the data to be encrypted
     * @param plainOffset the offset in <code>plain</code>
     * @param cipher the buffer for the encryption result
     * @param cipherOffset the offset in <code>cipher</code>
     */
    abstract void encryptBlock(byte[] plain, int plainOffset,
                          byte[] cipher, int cipherOffset);

    /**
     * Decrypt one cipher block.
     *
     * <p>The input <code>cipher</code>, starting at <code>cipherOffset</code>
     * and ending at <code>(cipherOffset+blockSize-1)</code>, is decrypted.
     * The result is stored in <code>plain</code>, starting at
     * <code>plainOffset</code>.
     *
     * @param cipher the input buffer with the data to be decrypted
     * @param cipherOffset the offset in <code>cipher</code>
     * @param plain the buffer for the decryption result
     * @param plainOffset the offset in <code>plain</code>
     */
    abstract void decryptBlock(byte[] cipher, int cipherOffset,
                          byte[] plain, int plainOffset);
    
    /**
     * Return the key bytes of the specified key. Throw an InvalidKeyException
     * if the key is not usable.
     */
    static byte[] getKeyBytes(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("No key given");
        }
        // note: key.getFormat() may return null
        if (!"RAW".equalsIgnoreCase(key.getFormat())) {
            throw new InvalidKeyException("Wrong format: RAW bytes needed");
        }
        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("RAW key bytes missing");
        }
        return keyBytes;
    }
}
