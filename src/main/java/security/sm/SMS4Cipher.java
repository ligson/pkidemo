package security.sm;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import security.ConstructKeys;

public class SMS4Cipher extends CipherSpi {

	/*
	 * internal buffer
	 */
	private byte[] buffer = null;

	/*
	 * blockSize
	 */
	private int blockSize = 0;

	/*
	 * unit size (number of input bytes that can be processed at a time)
	 */
	private int unitBytes = 0;

	/*
	 * index of the content size left in the buffer
	 */
	private int buffered = 0;

	/*
	 * minimum number of bytes in the buffer required for
	 * FeedbackCipher.encryptFinal()/decryptFinal() call. update() must buffer
	 * this many bytes before before starting to encrypt/decrypt data.
	 * currently, only CTS mode has a non-zero value due to its special handling
	 * on the last two blocks (the last one may be incomplete).
	 */
	private int minBytes = 0;

	/*
	 * number of bytes needed to make the total input length a multiple of the
	 * blocksize (this is used in feedback mode, when the number of input bytes
	 * that are processed at a time is different from the block size)
	 */
	private int diffBlocksize = 0;

	/*
	 * padding class
	 */
	private Padding padding = null;

	/*
	 * internal cipher engine
	 */
	private SymmetricCipher sms4Cipher;

	/*
	 * are we encrypting or decrypting?
	 */
	private boolean decrypting = false;

	public SMS4Cipher() {
		sms4Cipher = new SMS4Crypt();
		
		blockSize = sms4Cipher.getBlockSize();
        unitBytes = blockSize;
        diffBlocksize = blockSize;
        
        /*
         * The buffer should be usable for all cipher mode and padding
         * schemes. Thus, it has to be at least (blockSize+1) for CTS.
         * In decryption mode, it also hold the possible padding block.
         */
        buffer = new byte[blockSize*2];
        
		padding = new PKCS5Padding(blockSize);
	}

	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {
		return doFinal(input, inputOffset, inputLen);
	}

	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {
		return doFinal(input, inputOffset, inputLen, output, outputOffset);
	}

	@Override
	protected int engineGetBlockSize() {
		return blockSize;
	}

	@Override
	protected byte[] engineGetIV() {
		return null;
	}

	@Override
	protected int engineGetOutputSize(int inputLen) {
		return getOutputSize(inputLen);
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {
		return null;
	}

	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random)
			throws InvalidKeyException {
		try {
			this.engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
		} catch (InvalidAlgorithmParameterException e) {
			throw new InvalidKeyException(e.getMessage());
		}
	}

	@Override
	protected void engineInit(int opmode, Key key,
			AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		init(opmode, key);
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		IvParameterSpec ivSpec = null;
		if (params != null) {
			try {
				ivSpec = (IvParameterSpec) params
						.getParameterSpec(IvParameterSpec.class);
			} catch (InvalidParameterSpecException ipse) {
				throw new InvalidAlgorithmParameterException("Wrong parameter "
						+ "type: IV " + "expected");
			}
		}
		this.engineInit(opmode, key, ivSpec, random);
	}

	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
		if (mode.equalsIgnoreCase("ECB") == false) {
			throw new NoSuchAlgorithmException("Unsupported mode " + mode);
		}
	}

	@Override
	protected void engineSetPadding(String paddingName)
			throws NoSuchPaddingException {
		if (paddingName == null) {
			throw new NoSuchPaddingException("null padding");
		}
		if (paddingName.equalsIgnoreCase("NoPadding")) {
			padding = null;
		} else if (!paddingName.equalsIgnoreCase("PKCS5Padding")) {
			throw new NoSuchPaddingException("Padding: " + paddingName
					+ " not implemented");
		}
	}

	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		return update(input, inputOffset, inputLen);
	}

	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException {
		return update(input, inputOffset, inputLen, output, outputOffset);
	}

	protected int engineGetKeySize(Key key) throws InvalidKeyException {
		byte[] encoded = key.getEncoded();
		if (!SMS4Crypt.isKeySizeValid(encoded.length)) {
			throw new InvalidKeyException("Invalid SMS4 key length: "
					+ encoded.length + " bytes");
		}
		return encoded.length * 8;
	}

	protected byte[] engineWrap(Key key) throws IllegalBlockSizeException,
			InvalidKeyException {
		return wrap(key);
	}

	protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
			int wrappedKeyType) throws InvalidKeyException,
			NoSuchAlgorithmException {
		return unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
	}

	/**
	 * Initializes this cipher with a key, a set of algorithm parameters, and a
	 * source of randomness.
	 * 
	 * <p>
	 * The cipher is initialized for one of the following four operations:
	 * encryption, decryption, key wrapping or key unwrapping, depending on the
	 * value of <code>opmode</code>.
	 * 
	 * <p>
	 * If this cipher (including its underlying feedback or padding scheme)
	 * requires any random bytes, it will get them from <code>random</code>.
	 * 
	 * @param opmode
	 *            the operation mode of this cipher (this is one of the
	 *            following: <code>ENCRYPT_MODE</code>,
	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
	 *            <code>UNWRAP_MODE</code>)
	 * @param key
	 *            the encryption key
	 * @param params
	 *            the algorithm parameters
	 * @param random
	 *            the source of randomness
	 * 
	 * @exception InvalidKeyException
	 *                if the given key is inappropriate for initializing this
	 *                cipher
	 * @exception InvalidAlgorithmParameterException
	 *                if the given algorithm parameters are inappropriate for
	 *                this cipher
	 */
	void init(int opmode, Key key) throws InvalidKeyException {

		decrypting = (opmode == Cipher.DECRYPT_MODE)
				|| (opmode == Cipher.UNWRAP_MODE);

		byte[] keyBytes = SymmetricCipher.getKeyBytes(key);

		buffered = 0;
		diffBlocksize = blockSize;

		String algorithm = key.getAlgorithm();

		if (keyBytes == null) {
			throw new InvalidKeyException("Internal error");
		}

		sms4Cipher.init(decrypting, algorithm, keyBytes);
	}

	/**
	 * Continues a multiple-part encryption or decryption operation (depending
	 * on how this cipher was initialized), processing another data part.
	 * 
	 * <p>
	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
	 * starting at <code>inputOffset</code>, are processed, and the result is
	 * stored in a new buffer.
	 * 
	 * @param input
	 *            the input buffer
	 * @param inputOffset
	 *            the offset in <code>input</code> where the input starts
	 * @param inputLen
	 *            the input length
	 * 
	 * @return the new buffer with the result
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 */
	byte[] update(byte[] input, int inputOffset, int inputLen) {
		byte[] output = null;
		byte[] out = null;
		try {
			output = new byte[getOutputSize(inputLen)];
			int len = update(input, inputOffset, inputLen, output, 0);
			if (len == output.length) {
				out = output;
			} else {
				out = new byte[len];
				System.arraycopy(output, 0, out, 0, len);
			}
		} catch (ShortBufferException e) {
			// never thrown
		}
		return out;
	}

	/**
	 * Continues a multiple-part encryption or decryption operation (depending
	 * on how this cipher was initialized), processing another data part.
	 * 
	 * <p>
	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
	 * starting at <code>inputOffset</code>, are processed, and the result is
	 * stored in the <code>output</code> buffer, starting at
	 * <code>outputOffset</code>.
	 * 
	 * @param input
	 *            the input buffer
	 * @param inputOffset
	 *            the offset in <code>input</code> where the input starts
	 * @param inputLen
	 *            the input length
	 * @param output
	 *            the buffer for the result
	 * @param outputOffset
	 *            the offset in <code>output</code> where the result is stored
	 * 
	 * @return the number of bytes stored in <code>output</code>
	 * 
	 * @exception ShortBufferException
	 *                if the given output buffer is too small to hold the result
	 */
	int update(byte[] input, int inputOffset, int inputLen, byte[] output,
			int outputOffset) throws ShortBufferException {
		// figure out how much can be sent to crypto function
		int len = buffered + inputLen - minBytes;
		if (padding != null && decrypting) {
			// do not include the padding bytes when decrypting
			len -= blockSize;
		}
		// do not count the trailing bytes which do not make up a unit
		len = (len > 0 ? (len - (len % unitBytes)) : 0);

		// check output buffer capacity
		if ((output == null) || ((output.length - outputOffset) < len)) {
			throw new ShortBufferException("Output buffer must be "
					+ "(at least) " + len + " bytes long");
		}
		if (len != 0) {
			// there is some work to do
			byte[] in = new byte[len];

			int inputConsumed = len - buffered;
			int bufferedConsumed = buffered;
			if (inputConsumed < 0) {
				inputConsumed = 0;
				bufferedConsumed = len;
			}

			if (buffered != 0) {
				System.arraycopy(buffer, 0, in, 0, bufferedConsumed);
			}
			if (inputConsumed > 0) {
				System.arraycopy(input, inputOffset, in, bufferedConsumed,
						inputConsumed);
			}

			if (decrypting) {
				decrypt(in, 0, len, output, outputOffset);
			} else {
				encrypt(in, 0, len, output, outputOffset);
			}

			// Let's keep track of how many bytes are needed to make
			// the total input length a multiple of blocksize when
			// padding is applied
			if (unitBytes != blockSize) {
				if (len < diffBlocksize)
					diffBlocksize -= len;
				else
					diffBlocksize = blockSize
							- ((len - diffBlocksize) % blockSize);
			}

			inputLen -= inputConsumed;
			inputOffset += inputConsumed;
			outputOffset += len;
			buffered -= bufferedConsumed;
			if (buffered > 0) {
				System.arraycopy(buffer, bufferedConsumed, buffer, 0, buffered);
			}
		}
		// left over again
		if (inputLen > 0) {
			System.arraycopy(input, inputOffset, buffer, buffered, inputLen);
		}
		buffered += inputLen;
		return len;
	}

	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a
	 * multiple-part operation. The data is encrypted or decrypted, depending on
	 * how this cipher was initialized.
	 * 
	 * <p>
	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
	 * starting at <code>inputOffset</code>, and any input bytes that may have
	 * been buffered during a previous <code>update</code> operation, are
	 * processed, with padding (if requested) being applied. The result is
	 * stored in a new buffer.
	 * 
	 * <p>
	 * The cipher is reset to its initial state (uninitialized) after this call.
	 * 
	 * @param input
	 *            the input buffer
	 * @param inputOffset
	 *            the offset in <code>input</code> where the input starts
	 * @param inputLen
	 *            the input length
	 * 
	 * @return the new buffer with the result
	 * 
	 * @exception IllegalBlockSizeException
	 *                if this cipher is a block cipher, no padding has been
	 *                requested (only in encryption mode), and the total input
	 *                length of the data processed by this cipher is not a
	 *                multiple of block size
	 * @exception BadPaddingException
	 *                if this cipher is in decryption mode, and (un)padding has
	 *                been requested, but the decrypted data is not bounded by
	 *                the appropriate padding bytes
	 */
	byte[] doFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {
		byte[] output = null;
		byte[] out = null;
		try {
			output = new byte[getOutputSize(inputLen)];
			int len = doFinal(input, inputOffset, inputLen, output, 0);
			if (len < output.length) {
				out = new byte[len];
				if (len != 0)
					System.arraycopy(output, 0, out, 0, len);
			} else {
				out = output;
			}
		} catch (ShortBufferException e) {
			// never thrown
		}
		return out;
	}

	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a
	 * multiple-part operation. The data is encrypted or decrypted, depending on
	 * how this cipher was initialized.
	 * 
	 * <p>
	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
	 * starting at <code>inputOffset</code>, and any input bytes that may have
	 * been buffered during a previous <code>update</code> operation, are
	 * processed, with padding (if requested) being applied. The result is
	 * stored in the <code>output</code> buffer, starting at
	 * <code>outputOffset</code>.
	 * 
	 * <p>
	 * The cipher is reset to its initial state (uninitialized) after this call.
	 * 
	 * @param input
	 *            the input buffer
	 * @param inputOffset
	 *            the offset in <code>input</code> where the input starts
	 * @param inputLen
	 *            the input length
	 * @param output
	 *            the buffer for the result
	 * @param outputOffset
	 *            the offset in <code>output</code> where the result is stored
	 * 
	 * @return the number of bytes stored in <code>output</code>
	 * 
	 * @exception IllegalBlockSizeException
	 *                if this cipher is a block cipher, no padding has been
	 *                requested (only in encryption mode), and the total input
	 *                length of the data processed by this cipher is not a
	 *                multiple of block size
	 * @exception ShortBufferException
	 *                if the given output buffer is too small to hold the result
	 * @exception BadPaddingException
	 *                if this cipher is in decryption mode, and (un)padding has
	 *                been requested, but the decrypted data is not bounded by
	 *                the appropriate padding bytes
	 */
	int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
			int outputOffset) throws IllegalBlockSizeException,
			ShortBufferException, BadPaddingException {

		// calculate the total input length
		int totalLen = buffered + inputLen;
		int paddedLen = totalLen;
		int paddingLen = 0;

		// will the total input length be a multiple of blockSize?
		if (unitBytes != blockSize) {
			if (totalLen < diffBlocksize) {
				paddingLen = diffBlocksize - totalLen;
			} else {
				paddingLen = blockSize
						- ((totalLen - diffBlocksize) % blockSize);
			}
		} else if (padding != null) {
			paddingLen = padding.padLength(totalLen);
		}

		if ((paddingLen > 0) && (paddingLen != blockSize) && (padding != null)
				&& decrypting) {
			throw new IllegalBlockSizeException(
					"Input length must be multiple of " + blockSize
							+ " when decrypting with padded cipher");
		}

		// if encrypting and padding not null, add padding
		if (!decrypting && padding != null)
			paddedLen += paddingLen;

		// check output buffer capacity.
		// if we are decrypting with padding applied, we can perform this
		// check only after we have determined how many padding bytes there
		// are.
		if (output == null) {
			throw new ShortBufferException("Output buffer is null");
		}
		int outputCapacity = output.length - outputOffset;
		if (((!decrypting) || (padding == null))
				&& (outputCapacity < paddedLen)
				|| (decrypting && (outputCapacity < (paddedLen - blockSize)))) {
			throw new ShortBufferException("Output buffer too short: "
					+ outputCapacity + " bytes given, " + paddedLen
					+ " bytes needed");
		}

		// prepare the final input avoiding copying if possible
		byte[] finalBuf = input;
		int finalOffset = inputOffset;
		if ((buffered != 0) || (!decrypting && padding != null)) {
			finalOffset = 0;
			finalBuf = new byte[paddedLen];
			if (buffered != 0) {
				System.arraycopy(buffer, 0, finalBuf, 0, buffered);
			}
			if (inputLen != 0) {
				System.arraycopy(input, inputOffset, finalBuf, buffered,
						inputLen);
			}
			if (!decrypting && padding != null) {
				padding.padWithLen(finalBuf, totalLen, paddingLen);
			}
		}

		if (decrypting) {
			// if the size of specified output buffer is less than
			// the length of the cipher text, then the current
			// content of cipher has to be preserved in order for
			// users to retry the call with a larger buffer in the
			// case of ShortBufferException.
			if (outputCapacity < paddedLen) {
				save();
			}
			// create temporary output buffer so that only "real"
			// data bytes are passed to user's output buffer.
			byte[] outWithPadding = new byte[totalLen];
			totalLen = finalNoPadding(finalBuf, finalOffset, outWithPadding, 0,
					totalLen);

			if (padding != null) {
				int padStart = padding.unpad(outWithPadding, 0, totalLen);
				if (padStart < 0) {
					throw new BadPaddingException("Given final block not "
							+ "properly padded");
				}
				totalLen = padStart;
			}
			if ((output.length - outputOffset) < totalLen) {
				// restore so users can retry with a larger buffer
				restore();
				throw new ShortBufferException("Output buffer too short: "
						+ (output.length - outputOffset) + " bytes given, "
						+ totalLen + " bytes needed");
			}
			for (int i = 0; i < totalLen; i++) {
				output[outputOffset + i] = outWithPadding[i];
			}
		} else { // encrypting
			totalLen = finalNoPadding(finalBuf, finalOffset, output,
					outputOffset, paddedLen);
		}

		buffered = 0;
		diffBlocksize = blockSize;
		return totalLen;
	}

	private int finalNoPadding(byte[] in, int inOff, byte[] out, int outOff,
			int len) throws IllegalBlockSizeException {
		if (in == null || len == 0)
			return 0;

		if ((len % unitBytes) != 0) {
			if (padding != null) {
				throw new IllegalBlockSizeException(
						"Input length (with padding) not multiple of "
								+ unitBytes + " bytes");
			} else {
				throw new IllegalBlockSizeException(
						"Input length not multiple of " + unitBytes + " bytes");
			}
		}

		if (decrypting) {
			decrypt(in, inOff, len, out, outOff);
		} else {
			encrypt(in, inOff, len, out, outOff);
		}

		return len;
	}

	// Note: Wrap() and Unwrap() are the same in
	// each of SunJCE CipherSpi implementation classes.
	// They are duplicated due to export control requirements:
	// All CipherSpi implementation must be final.
	/**
	 * Wrap a key.
	 * 
	 * @param key
	 *            the key to be wrapped.
	 * 
	 * @return the wrapped key.
	 * 
	 * @exception IllegalBlockSizeException
	 *                if this cipher is a block cipher, no padding has been
	 *                requested, and the length of the encoding of the key to be
	 *                wrapped is not a multiple of the block size.
	 * 
	 * @exception InvalidKeyException
	 *                if it is impossible or unsafe to wrap the key with this
	 *                cipher (e.g., a hardware protected key is being passed to
	 *                a software only cipher).
	 */
	byte[] wrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
		byte[] result = null;

		try {
			byte[] encodedKey = key.getEncoded();
			if ((encodedKey == null) || (encodedKey.length == 0)) {
				throw new InvalidKeyException("Cannot get an encoding of "
						+ "the key to be wrapped");
			}
			result = doFinal(encodedKey, 0, encodedKey.length);
		} catch (BadPaddingException e) {
			// Should never happen
		}
		return result;
	}

	/**
	 * Unwrap a previously wrapped key.
	 * 
	 * @param wrappedKey
	 *            the key to be unwrapped.
	 * 
	 * @param wrappedKeyAlgorithm
	 *            the algorithm the wrapped key is for.
	 * 
	 * @param wrappedKeyType
	 *            the type of the wrapped key. This is one of
	 *            <code>Cipher.SECRET_KEY</code>,
	 *            <code>Cipher.PRIVATE_KEY</code>, or
	 *            <code>Cipher.PUBLIC_KEY</code>.
	 * 
	 * @return the unwrapped key.
	 * 
	 * @exception NoSuchAlgorithmException
	 *                if no installed providers can create keys of type
	 *                <code>wrappedKeyType</code> for the
	 *                <code>wrappedKeyAlgorithm</code>.
	 * 
	 * @exception InvalidKeyException
	 *                if <code>wrappedKey</code> does not represent a wrapped
	 *                key of type <code>wrappedKeyType</code> for the
	 *                <code>wrappedKeyAlgorithm</code>.
	 */
	Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
			throws InvalidKeyException, NoSuchAlgorithmException {
		byte[] encodedKey;
		try {
			encodedKey = doFinal(wrappedKey, 0, wrappedKey.length);
		} catch (BadPaddingException ePadding) {
			throw new InvalidKeyException("The wrapped key is not padded "
					+ "correctly");
		} catch (IllegalBlockSizeException eBlockSize) {
			throw new InvalidKeyException("The wrapped key does not have "
					+ "the correct length");
		}
		return ConstructKeys.constructKey(encodedKey, wrappedKeyAlgorithm,
				wrappedKeyType);
	}

	int getOutputSize(int inputLen) {
		int totalLen = buffered + inputLen;

		if (padding == null)
			return totalLen;

		if (decrypting)
			return totalLen;

		if (unitBytes != blockSize) {
			if (totalLen < diffBlocksize)
				return diffBlocksize;
			else
				return (totalLen + blockSize - ((totalLen - diffBlocksize) % blockSize));
		} else {
			return totalLen + padding.padLength(totalLen);
		}
	}

	/**
	 * Performs encryption operation.
	 * 
	 * <p>
	 * The input plain text <code>plain</code>, starting at
	 * <code>plainOffset</code> and ending at
	 * <code>(plainOffset + len - 1)</code>, is encrypted. The result is stored
	 * in <code>cipher</code>, starting at <code>cipherOffset</code>.
	 * 
	 * <p>
	 * It is the application's responsibility to make sure that
	 * <code>plainLen</code> is a multiple of the embedded cipher's block size,
	 * as any excess bytes are ignored.
	 * 
	 * <p>
	 * It is also the application's responsibility to make sure that
	 * <code>init</code> has been called before this method is called. (This
	 * check is omitted here, to avoid double checking.)
	 * 
	 * @param in
	 *            the buffer with the input data to be encrypted
	 * @param inOffset
	 *            the offset in <code>plain</code>
	 * @param len
	 *            the length of the input data
	 * @param out
	 *            the buffer for the result
	 * @param outOff
	 *            the offset in <code>cipher</code>
	 */
	void encrypt(byte[] in, int inOff, int len, byte[] out, int outOff) {
		while (len >= blockSize) {
			sms4Cipher.encryptBlock(in, inOff, out, outOff);
			len -= blockSize;
			inOff += blockSize;
			outOff += blockSize;
		}
	}

	/**
	 * Performs decryption operation.
	 * 
	 * <p>
	 * The input cipher text <code>cipher</code>, starting at
	 * <code>cipherOffset</code> and ending at
	 * <code>(cipherOffset + len - 1)</code>, is decrypted. The result is stored
	 * in <code>plain</code>, starting at <code>plainOffset</code>.
	 * 
	 * <p>
	 * It is the application's responsibility to make sure that
	 * <code>cipherLen</code> is a multiple of the embedded cipher's block size,
	 * as any excess bytes are ignored.
	 * 
	 * <p>
	 * It is also the application's responsibility to make sure that
	 * <code>init</code> has been called before this method is called. (This
	 * check is omitted here, to avoid double checking.)
	 * 
	 * @param in
	 *            the buffer with the input data to be decrypted
	 * @param inOff
	 *            the offset in <code>cipherOffset</code>
	 * @param len
	 *            the length of the input data
	 * @param out
	 *            the buffer for the result
	 * @param outOff
	 *            the offset in <code>plain</code>
	 */
	void decrypt(byte[] in, int inOff, int len, byte[] out, int outOff) {
		while (len >= blockSize) {
			sms4Cipher.decryptBlock(in, inOff, out, outOff);
			len -= blockSize;
			inOff += blockSize;
			outOff += blockSize;
		}
	}

	/**
	 * Save the current content of this cipher.
	 */
	void save() {
	}

	/**
	 * Restores the content of this cipher to the previous saved one.
	 */
	void restore() {
	}
}
