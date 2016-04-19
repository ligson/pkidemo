package security.sm;

/**
 * This class defines the constants used by the SM4S implementation.
 *
 * @see SMS4Cipher
 */

interface SMS4Constants {

    // SM4S block size in bytes.
	int SMS4_BLOCK_SIZE = 16;

    // Valid SM4S key sizes in bytes.
    int[] SMS4_KEYSIZES = { 16 };
}
