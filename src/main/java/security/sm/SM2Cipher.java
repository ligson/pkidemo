package security.sm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import security.ConstructKeys;
import security.ec.NamedCurve;

public class SM2Cipher extends CipherSpi {

	@SuppressWarnings("unused")
	private final static Logger log = LoggerFactory.getLogger("TopSMProvider");

	// constant for an empty byte array
	private final static byte[] B0 = new byte[0];

	// constant for raw RSA
	private final static String PAD_NONE = "NoPadding";

	// active padding type, one of PAD_* above. Set by setPadding()
	private String paddingType;

	// padding object
	private SM2Padding padding;

	// the public key, if we were initialized using a public key
	private SM2PublicKey publicKey;
	// the private key, if we were initialized using a private key
	private SM2PrivateKey privateKey;
	// the c3 generator
	private MessageDigest c3Gen;
	private boolean digestReset;
	// buffer for the data
	private ByteArrayOutputStream buffer;

	public SM2Cipher() {
		// TopSMProvider.ensureIntegrity(getClass());
		paddingType = "NOPADDING";
		try {
			this.c3Gen = MessageDigest.getInstance("SM3");
		} catch (NoSuchAlgorithmException e) {
			throw new ProviderException(e);
		}
		this.digestReset = true;
	}

	@Override
	protected byte[] engineDoFinal(byte[] in, int inOfs, int inLen)
			throws IllegalBlockSizeException, BadPaddingException {
		_update(in, inOfs, inLen);
		return _doFinal();
	}

	@Override
	protected int engineDoFinal(byte[] in, int inOfs, int inLen, byte[] out,
			int outOfs) throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {

		_update(in, inOfs, inLen);
		int outputSize = buffer.size();
		if (outputSize > out.length - outOfs) {
			throw new ShortBufferException("Need " + outputSize
					+ " bytes for output");
		}
		byte[] result = _doFinal();
		int n = result.length;
		System.arraycopy(result, 0, out, outOfs, n);
		return n;
	}

	// return 0 as block size, we are not a block cipher
	@Override
	protected int engineGetBlockSize() {
		return 0;
	}

	// no iv, return null
	@Override
	protected byte[] engineGetIV() {
		return null;
	}

	// return the output size
	@Override
	protected int engineGetOutputSize(int inputLen) {
		return inputLen;
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {
		return null;
	}

	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random)
			throws InvalidKeyException {
		try {
			_init(opmode, key, random, null);
		} catch (InvalidAlgorithmParameterException iape) {
			// never thrown when null parameters are used;
			// but re-throw it just in case
			InvalidKeyException ike = new InvalidKeyException(
					"Wrong parameters");
			ike.initCause(iape);
			throw ike;
		}
	}

	@Override
	protected void engineInit(int opmode, Key key,
			AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		_init(opmode, key, random, params);
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		if (params == null) {
			_init(opmode, key, random, null);
		} else {
			try {
				NamedCurve spec = (NamedCurve) params
						.getParameterSpec(NamedCurve.class);
				_init(opmode, key, random, spec);
			} catch (InvalidParameterSpecException ipse) {
				InvalidAlgorithmParameterException iape = new InvalidAlgorithmParameterException(
						"Wrong parameter");
				iape.initCause(ipse);
				throw iape;
			}
		}
	}

	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
		// if (mode.equalsIgnoreCase("ECB") == false) {
		// throw new NoSuchAlgorithmException("Unsupported mode " + mode);
		// }
	}

	@Override
	protected void engineSetPadding(String paddingName)
			throws NoSuchPaddingException {
		// if (paddingName.equalsIgnoreCase(PAD_NONE)) {
		// paddingType = PAD_NONE;
		// } else {
		// throw new NoSuchPaddingException("Padding " + paddingName
		// + " not supported");
		// }
	}

	@Override
	protected byte[] engineUpdate(byte[] in, int inOfs, int inLen) {
		_update(in, inOfs, inLen);
		return B0;
	}

	@Override
	protected int engineUpdate(byte[] in, int inOfs, int inLen, byte[] out,
			int outOfs) throws ShortBufferException {
		_update(in, inOfs, inLen);
		return 0;
	}

	protected byte[] engineWrap(Key key) throws InvalidKeyException,
			IllegalBlockSizeException {
		byte[] encoded = key.getEncoded();
		if ((encoded == null) || (encoded.length == 0)) {
			throw new InvalidKeyException("Could not obtain encoded key");
		}
		_update(encoded, 0, encoded.length);
		try {
			return _doFinal();
		} catch (BadPaddingException e) {
			// should not occur
			throw new InvalidKeyException("Wrapping failed", e);
		}
	}

	protected Key engineUnwrap(byte[] wrappedKey, String algorithm, int type)
			throws InvalidKeyException, NoSuchAlgorithmException {
		_update(wrappedKey, 0, wrappedKey.length);
		try {
			byte[] encoded = _doFinal();
			return ConstructKeys.constructKey(encoded, algorithm, type);
		} catch (BadPaddingException e) {
			// should not occur
			throw new InvalidKeyException("Unwrapping failed", e);
		} catch (IllegalBlockSizeException e) {
			// should not occur, handled with length check above
			throw new InvalidKeyException("Unwrapping failed", e);
		}
	}

	protected int engineGetKeySize(Key key) throws InvalidKeyException {
		ECKey ecKey = SM2KeyFactory.toSM2Key(key);
		return ecKey.getParams().getCurve().getField().getFieldSize();
	}

	// initialize this cipher
	private void _init(int opmode, Key key, SecureRandom random,
			AlgorithmParameterSpec params) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		_resetDigest();
		ECKey sm2Key = SM2KeyFactory.toSM2Key(key);
		switch (opmode) {
		case Cipher.ENCRYPT_MODE:
		case Cipher.WRAP_MODE:
			this.publicKey = (SM2PublicKey) sm2Key;
			this.privateKey = null;
			break;
		case Cipher.DECRYPT_MODE:
		case Cipher.UNWRAP_MODE:
			this.privateKey = (SM2PrivateKey) sm2Key;
			this.publicKey = null;
			break;
		default:
			throw new InvalidKeyException("Unknown mode: " + opmode);
		}
		if (paddingType.equalsIgnoreCase(PAD_NONE) || true)
			padding = SM2Padding.getInstance(SM2Padding.PAD_NONE, random);
		buffer = new ByteArrayOutputStream();
	}

	// internal update method
	private void _update(byte[] in, int inOfs, int inLen) {
		buffer.write(in, inOfs, inLen);
	}

	// internal doFinal() method. Here we perform the actual SM2 operation
	private byte[] _doFinal() throws BadPaddingException,
			IllegalBlockSizeException {
		try {
			byte[] data = null;
			if (this.publicKey != null) {
				data = padding.pad(buffer.toByteArray());
				return _encrypt(data, publicKey);
			} else {
				try {
					data = _decrypt(buffer.toByteArray(), privateKey);
				} catch (IOException e) {
					throw new BadPaddingException(e.getMessage());
				}
				return padding.unpad(data);
			}
		} finally {
			_resetDigest();
		}
	}

	private byte[] _encrypt(byte[] data, SM2PublicKey publicKey) {
		SM2Core sm2 = new SM2Core(publicKey);
		SM2EncData encData = new SM2EncData();
		encData.setC1Point(sm2.c1Point());
		encData.setC2Data(sm2.c2Data(data));
		encData.setC3Hash(sm2.c3Hash(data));
		return encData.getEncoded();
	}

	private byte[] _decrypt(byte[] data, SM2PrivateKey privateKey)
			throws IOException, BadPaddingException {
		SM2EncData encData = new SM2EncData(data);
		SM2Core sm2 = new SM2Core(encData.getC1Point(), privateKey);
		byte[] origin = sm2.c2Data(encData.getC2Data());
		byte[] hash = sm2.c3Hash(origin);
		if (Arrays.equals(hash, encData.getC3Hash())) {
			return origin;
		} else {
			throw new BadPaddingException("Invalid data, verify hash fail.");
		}
	}

	private void _resetDigest() {
		if (!(this.digestReset)) {
			this.c3Gen.reset();
			this.digestReset = true;
		}
	}

//	// XXX use cn.topca.crypto.CipherProxy instead
//	// ===================================================
//	private static final SM2Cipher INSTANCE = new SM2Cipher();
//	private Cipher cipher = null;
//
//	private SM2Cipher(Cipher cipher) {
//		log.debug("#compatibility");
//		log.debug("use JCE Cipher for " + cipher.getAlgorithm());
//		this.cipher = cipher;
//	}
//
//	public static SM2Cipher getInstance(String transformation)
//			throws NoSuchAlgorithmException, NoSuchPaddingException {
//		if (!transformation.startsWith("SM2")) {
//			return new SM2Cipher(Cipher.getInstance(transformation));
//		}
//		return INSTANCE;
//	}
//
//	/**
//	 * Returns the provider of this <code>Cipher</code> object.
//	 * 
//	 * @return the provider of this <code>Cipher</code> object
//	 */
//	public final Provider getProvider() {
//		if (cipher != null) {
//			return cipher.getProvider();
//		}
//		Provider provider = Security.getProvider(TopSMProvider.NAME);
//		if (provider == null)
//			provider = new TopSMProvider();
//		return provider;
//	}
//
//	/**
//	 * Returns the algorithm name of this <code>Cipher</code> object.
//	 * 
//	 * <p>
//	 * This is the same name that was specified in one of the
//	 * <code>getInstance</code> calls that created this <code>Cipher</code>
//	 * object..
//	 * 
//	 * @return the algorithm name of this <code>Cipher</code> object.
//	 */
//	public final String getAlgorithm() {
//		if (cipher != null) {
//			return cipher.getAlgorithm();
//		}
//		return "SM2";
//	}
//
//	/**
//	 * Returns the block size (in bytes).
//	 * 
//	 * @return the block size (in bytes), or 0 if the underlying algorithm is
//	 *         not a block cipher
//	 */
//	public final int getBlockSize() {
//		if (cipher != null) {
//			return cipher.getBlockSize();
//		}
//		return this.engineGetBlockSize();
//	}
//
//	/**
//	 * Returns the length in bytes that an output buffer would need to be in
//	 * order to hold the result of the next <code>update</code> or
//	 * <code>doFinal</code> operation, given the input length
//	 * <code>inputLen</code> (in bytes).
//	 * 
//	 * <p>
//	 * This call takes into account any unprocessed (buffered) data from a
//	 * previous <code>update</code> call, padding, and AEAD tagging.
//	 * 
//	 * <p>
//	 * The actual output length of the next <code>update</code> or
//	 * <code>doFinal</code> call may be smaller than the length returned by this
//	 * method.
//	 * 
//	 * @param inputLen
//	 *            the input length (in bytes)
//	 * 
//	 * @return the required output buffer size (in bytes)
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not yet been
//	 *                initialized)
//	 */
//	public final int getOutputSize(int inputLen) {
//		if (cipher != null) {
//			return cipher.getOutputSize(inputLen);
//		}
//		return this.engineGetOutputSize(inputLen);
//	}
//
//	/**
//	 * Returns the initialization vector (IV) in a new buffer.
//	 * 
//	 * <p>
//	 * This is useful in the case where a random IV was created, or in the
//	 * context of password-based encryption or decryption, where the IV is
//	 * derived from a user-supplied password.
//	 * 
//	 * @return the initialization vector in a new buffer, or null if the
//	 *         underlying algorithm does not use an IV, or if the IV has not yet
//	 *         been set.
//	 */
//	public final byte[] getIV() {
//		if (cipher != null) {
//			return cipher.getIV();
//		}
//		return this.engineGetIV();
//	}
//
//	/**
//	 * Returns the parameters used with this cipher.
//	 * 
//	 * <p>
//	 * The returned parameters may be the same that were used to initialize this
//	 * cipher, or may contain a combination of default and random parameter
//	 * values used by the underlying cipher implementation if this cipher
//	 * requires algorithm parameters but was not initialized with any.
//	 * 
//	 * @return the parameters used with this cipher, or null if this cipher does
//	 *         not use any parameters.
//	 */
//	public final AlgorithmParameters getParameters() {
//		if (cipher != null) {
//			return cipher.getParameters();
//		}
//		return this.engineGetParameters();
//	}
//
//	/**
//	 * Initializes this cipher with a key.
//	 * 
//	 * <p>
//	 * The cipher is initialized for one of the following four operations:
//	 * encryption, decryption, key wrapping or key unwrapping, depending on the
//	 * value of <code>opmode</code>.
//	 * 
//	 * <p>
//	 * If this cipher requires any algorithm parameters that cannot be derived
//	 * from the given <code>key</code>, the underlying cipher implementation is
//	 * supposed to generate the required parameters itself (using
//	 * provider-specific default or random values) if it is being initialized
//	 * for encryption or key wrapping, and raise an
//	 * <code>InvalidKeyException</code> if it is being initialized for
//	 * decryption or key unwrapping. The generated parameters can be retrieved
//	 * using {@link #getParameters() getParameters} or {@link #getIV() getIV}
//	 * (if the parameter is an IV).
//	 * 
//	 * <p>
//	 * If this cipher requires algorithm parameters that cannot be derived from
//	 * the input parameters, and there are no reasonable provider-specific
//	 * default values, initialization will necessarily fail.
//	 * 
//	 * <p>
//	 * If this cipher (including its underlying feedback or padding scheme)
//	 * requires any random bytes (e.g., for parameter generation), it will get
//	 * them using the {@link SecureRandom <code>SecureRandom</code>}
//	 * implementation of the highest-priority installed provider as the source
//	 * of randomness. (If none of the installed providers supply an
//	 * implementation of SecureRandom, a system-provided source of randomness
//	 * will be used.)
//	 * 
//	 * <p>
//	 * Note that when a Cipher object is initialized, it loses all
//	 * previously-acquired state. In other words, initializing a Cipher is
//	 * equivalent to creating a new instance of that Cipher and initializing it.
//	 * 
//	 * @param opmode
//	 *            the operation mode of this cipher (this is one of the
//	 *            following: <code>ENCRYPT_MODE</code>,
//	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
//	 *            <code>UNWRAP_MODE</code>)
//	 * @param key
//	 *            the key
//	 * 
//	 * @exception InvalidKeyException
//	 *                if the given key is inappropriate for initializing this
//	 *                cipher, or requires algorithm parameters that cannot be
//	 *                determined from the given key, or if the given key has a
//	 *                keysize that exceeds the maximum allowable keysize (as
//	 *                determined from the configured jurisdiction policy files).
//	 */
//	public final void init(int opmode, Key key) throws InvalidKeyException {
//		if (cipher != null) {
//			cipher.init(opmode, key);
//			return;
//		}
//		this.engineInit(opmode, key, null);
//	}
//
//	/**
//	 * Initializes this cipher with a key and a source of randomness.
//	 * 
//	 * <p>
//	 * The cipher is initialized for one of the following four operations:
//	 * encryption, decryption, key wrapping or key unwrapping, depending on the
//	 * value of <code>opmode</code>.
//	 * 
//	 * <p>
//	 * If this cipher requires any algorithm parameters that cannot be derived
//	 * from the given <code>key</code>, the underlying cipher implementation is
//	 * supposed to generate the required parameters itself (using
//	 * provider-specific default or random values) if it is being initialized
//	 * for encryption or key wrapping, and raise an
//	 * <code>InvalidKeyException</code> if it is being initialized for
//	 * decryption or key unwrapping. The generated parameters can be retrieved
//	 * using {@link #getParameters() getParameters} or {@link #getIV() getIV}
//	 * (if the parameter is an IV).
//	 * 
//	 * <p>
//	 * If this cipher requires algorithm parameters that cannot be derived from
//	 * the input parameters, and there are no reasonable provider-specific
//	 * default values, initialization will necessarily fail.
//	 * 
//	 * <p>
//	 * If this cipher (including its underlying feedback or padding scheme)
//	 * requires any random bytes (e.g., for parameter generation), it will get
//	 * them from <code>random</code>.
//	 * 
//	 * <p>
//	 * Note that when a Cipher object is initialized, it loses all
//	 * previously-acquired state. In other words, initializing a Cipher is
//	 * equivalent to creating a new instance of that Cipher and initializing it.
//	 * 
//	 * @param opmode
//	 *            the operation mode of this cipher (this is one of the
//	 *            following: <code>ENCRYPT_MODE</code>,
//	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
//	 *            <code>UNWRAP_MODE</code>)
//	 * @param key
//	 *            the encryption key
//	 * @param random
//	 *            the source of randomness
//	 * 
//	 * @exception InvalidKeyException
//	 *                if the given key is inappropriate for initializing this
//	 *                cipher, or requires algorithm parameters that cannot be
//	 *                determined from the given key, or if the given key has a
//	 *                keysize that exceeds the maximum allowable keysize (as
//	 *                determined from the configured jurisdiction policy files).
//	 */
//	public final void init(int opmode, Key key, SecureRandom random)
//			throws InvalidKeyException {
//		if (cipher != null) {
//			cipher.init(opmode, key, random);
//			return;
//		}
//		this.engineInit(opmode, key, random);
//	}
//
//	/**
//	 * Initializes this cipher with a key and a set of algorithm parameters.
//	 * 
//	 * <p>
//	 * The cipher is initialized for one of the following four operations:
//	 * encryption, decryption, key wrapping or key unwrapping, depending on the
//	 * value of <code>opmode</code>.
//	 * 
//	 * <p>
//	 * If this cipher requires any algorithm parameters and <code>params</code>
//	 * is null, the underlying cipher implementation is supposed to generate the
//	 * required parameters itself (using provider-specific default or random
//	 * values) if it is being initialized for encryption or key wrapping, and
//	 * raise an <code>InvalidAlgorithmParameterException</code> if it is being
//	 * initialized for decryption or key unwrapping. The generated parameters
//	 * can be retrieved using {@link #getParameters() getParameters} or
//	 * {@link #getIV() getIV} (if the parameter is an IV).
//	 * 
//	 * <p>
//	 * If this cipher requires algorithm parameters that cannot be derived from
//	 * the input parameters, and there are no reasonable provider-specific
//	 * default values, initialization will necessarily fail.
//	 * 
//	 * <p>
//	 * If this cipher (including its underlying feedback or padding scheme)
//	 * requires any random bytes (e.g., for parameter generation), it will get
//	 * them using the {@link SecureRandom <code>SecureRandom</code>}
//	 * implementation of the highest-priority installed provider as the source
//	 * of randomness. (If none of the installed providers supply an
//	 * implementation of SecureRandom, a system-provided source of randomness
//	 * will be used.)
//	 * 
//	 * <p>
//	 * Note that when a Cipher object is initialized, it loses all
//	 * previously-acquired state. In other words, initializing a Cipher is
//	 * equivalent to creating a new instance of that Cipher and initializing it.
//	 * 
//	 * @param opmode
//	 *            the operation mode of this cipher (this is one of the
//	 *            following: <code>ENCRYPT_MODE</code>,
//	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
//	 *            <code>UNWRAP_MODE</code>)
//	 * @param key
//	 *            the encryption key
//	 * @param params
//	 *            the algorithm parameters
//	 * 
//	 * @exception InvalidKeyException
//	 *                if the given key is inappropriate for initializing this
//	 *                cipher, or its keysize exceeds the maximum allowable
//	 *                keysize (as determined from the configured jurisdiction
//	 *                policy files).
//	 * @exception InvalidAlgorithmParameterException
//	 *                if the given algorithm parameters are inappropriate for
//	 *                this cipher, or this cipher requires algorithm parameters
//	 *                and <code>params</code> is null, or the given algorithm
//	 *                parameters imply a cryptographic strength that would
//	 *                exceed the legal limits (as determined from the configured
//	 *                jurisdiction policy files).
//	 */
//	public final void init(int opmode, Key key, AlgorithmParameterSpec params)
//			throws InvalidKeyException, InvalidAlgorithmParameterException {
//		if (cipher != null) {
//			cipher.init(opmode, key, params);
//			return;
//		}
//		init(opmode, key, params, null);
//	}
//
//	/**
//	 * Initializes this cipher with a key, a set of algorithm parameters, and a
//	 * source of randomness.
//	 * 
//	 * <p>
//	 * The cipher is initialized for one of the following four operations:
//	 * encryption, decryption, key wrapping or key unwrapping, depending on the
//	 * value of <code>opmode</code>.
//	 * 
//	 * <p>
//	 * If this cipher requires any algorithm parameters and <code>params</code>
//	 * is null, the underlying cipher implementation is supposed to generate the
//	 * required parameters itself (using provider-specific default or random
//	 * values) if it is being initialized for encryption or key wrapping, and
//	 * raise an <code>InvalidAlgorithmParameterException</code> if it is being
//	 * initialized for decryption or key unwrapping. The generated parameters
//	 * can be retrieved using {@link #getParameters() getParameters} or
//	 * {@link #getIV() getIV} (if the parameter is an IV).
//	 * 
//	 * <p>
//	 * If this cipher requires algorithm parameters that cannot be derived from
//	 * the input parameters, and there are no reasonable provider-specific
//	 * default values, initialization will necessarily fail.
//	 * 
//	 * <p>
//	 * If this cipher (including its underlying feedback or padding scheme)
//	 * requires any random bytes (e.g., for parameter generation), it will get
//	 * them from <code>random</code>.
//	 * 
//	 * <p>
//	 * Note that when a Cipher object is initialized, it loses all
//	 * previously-acquired state. In other words, initializing a Cipher is
//	 * equivalent to creating a new instance of that Cipher and initializing it.
//	 * 
//	 * @param opmode
//	 *            the operation mode of this cipher (this is one of the
//	 *            following: <code>ENCRYPT_MODE</code>,
//	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
//	 *            <code>UNWRAP_MODE</code>)
//	 * @param key
//	 *            the encryption key
//	 * @param params
//	 *            the algorithm parameters
//	 * @param random
//	 *            the source of randomness
//	 * 
//	 * @exception InvalidKeyException
//	 *                if the given key is inappropriate for initializing this
//	 *                cipher, or its keysize exceeds the maximum allowable
//	 *                keysize (as determined from the configured jurisdiction
//	 *                policy files).
//	 * @exception InvalidAlgorithmParameterException
//	 *                if the given algorithm parameters are inappropriate for
//	 *                this cipher, or this cipher requires algorithm parameters
//	 *                and <code>params</code> is null, or the given algorithm
//	 *                parameters imply a cryptographic strength that would
//	 *                exceed the legal limits (as determined from the configured
//	 *                jurisdiction policy files).
//	 */
//	public final void init(int opmode, Key key, AlgorithmParameterSpec params,
//			SecureRandom random) throws InvalidKeyException,
//			InvalidAlgorithmParameterException {
//		if (cipher != null) {
//			cipher.init(opmode, key, params, random);
//			return;
//		}
//		this.engineInit(opmode, key, params, random);
//	}
//
//	/**
//	 * Initializes this cipher with a key and a set of algorithm parameters.
//	 * 
//	 * <p>
//	 * The cipher is initialized for one of the following four operations:
//	 * encryption, decryption, key wrapping or key unwrapping, depending on the
//	 * value of <code>opmode</code>.
//	 * 
//	 * <p>
//	 * If this cipher requires any algorithm parameters and <code>params</code>
//	 * is null, the underlying cipher implementation is supposed to generate the
//	 * required parameters itself (using provider-specific default or random
//	 * values) if it is being initialized for encryption or key wrapping, and
//	 * raise an <code>InvalidAlgorithmParameterException</code> if it is being
//	 * initialized for decryption or key unwrapping. The generated parameters
//	 * can be retrieved using {@link #getParameters() getParameters} or
//	 * {@link #getIV() getIV} (if the parameter is an IV).
//	 * 
//	 * <p>
//	 * If this cipher requires algorithm parameters that cannot be derived from
//	 * the input parameters, and there are no reasonable provider-specific
//	 * default values, initialization will necessarily fail.
//	 * 
//	 * <p>
//	 * If this cipher (including its underlying feedback or padding scheme)
//	 * requires any random bytes (e.g., for parameter generation), it will get
//	 * them using the {@link SecureRandom <code>SecureRandom</code>}
//	 * implementation of the highest-priority installed provider as the source
//	 * of randomness. (If none of the installed providers supply an
//	 * implementation of SecureRandom, a system-provided source of randomness
//	 * will be used.)
//	 * 
//	 * <p>
//	 * Note that when a Cipher object is initialized, it loses all
//	 * previously-acquired state. In other words, initializing a Cipher is
//	 * equivalent to creating a new instance of that Cipher and initializing it.
//	 * 
//	 * @param opmode
//	 *            the operation mode of this cipher (this is one of the
//	 *            following: <code>ENCRYPT_MODE</code>,
//	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
//	 *            <code>UNWRAP_MODE</code>)
//	 * @param key
//	 *            the encryption key
//	 * @param params
//	 *            the algorithm parameters
//	 * 
//	 * @exception InvalidKeyException
//	 *                if the given key is inappropriate for initializing this
//	 *                cipher, or its keysize exceeds the maximum allowable
//	 *                keysize (as determined from the configured jurisdiction
//	 *                policy files).
//	 * @exception InvalidAlgorithmParameterException
//	 *                if the given algorithm parameters are inappropriate for
//	 *                this cipher, or this cipher requires algorithm parameters
//	 *                and <code>params</code> is null, or the given algorithm
//	 *                parameters imply a cryptographic strength that would
//	 *                exceed the legal limits (as determined from the configured
//	 *                jurisdiction policy files).
//	 */
//	public final void init(int opmode, Key key, AlgorithmParameters params)
//			throws InvalidKeyException, InvalidAlgorithmParameterException {
//		if (cipher != null) {
//			cipher.init(opmode, key, params);
//			return;
//		}
//		init(opmode, key, params, null);
//	}
//
//	/**
//	 * Initializes this cipher with a key, a set of algorithm parameters, and a
//	 * source of randomness.
//	 * 
//	 * <p>
//	 * The cipher is initialized for one of the following four operations:
//	 * encryption, decryption, key wrapping or key unwrapping, depending on the
//	 * value of <code>opmode</code>.
//	 * 
//	 * <p>
//	 * If this cipher requires any algorithm parameters and <code>params</code>
//	 * is null, the underlying cipher implementation is supposed to generate the
//	 * required parameters itself (using provider-specific default or random
//	 * values) if it is being initialized for encryption or key wrapping, and
//	 * raise an <code>InvalidAlgorithmParameterException</code> if it is being
//	 * initialized for decryption or key unwrapping. The generated parameters
//	 * can be retrieved using {@link #getParameters() getParameters} or
//	 * {@link #getIV() getIV} (if the parameter is an IV).
//	 * 
//	 * <p>
//	 * If this cipher requires algorithm parameters that cannot be derived from
//	 * the input parameters, and there are no reasonable provider-specific
//	 * default values, initialization will necessarily fail.
//	 * 
//	 * <p>
//	 * If this cipher (including its underlying feedback or padding scheme)
//	 * requires any random bytes (e.g., for parameter generation), it will get
//	 * them from <code>random</code>.
//	 * 
//	 * <p>
//	 * Note that when a Cipher object is initialized, it loses all
//	 * previously-acquired state. In other words, initializing a Cipher is
//	 * equivalent to creating a new instance of that Cipher and initializing it.
//	 * 
//	 * @param opmode
//	 *            the operation mode of this cipher (this is one of the
//	 *            following: <code>ENCRYPT_MODE</code>,
//	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
//	 *            <code>UNWRAP_MODE</code>)
//	 * @param key
//	 *            the encryption key
//	 * @param params
//	 *            the algorithm parameters
//	 * @param random
//	 *            the source of randomness
//	 * 
//	 * @exception InvalidKeyException
//	 *                if the given key is inappropriate for initializing this
//	 *                cipher, or its keysize exceeds the maximum allowable
//	 *                keysize (as determined from the configured jurisdiction
//	 *                policy files).
//	 * @exception InvalidAlgorithmParameterException
//	 *                if the given algorithm parameters are inappropriate for
//	 *                this cipher, or this cipher requires algorithm parameters
//	 *                and <code>params</code> is null, or the given algorithm
//	 *                parameters imply a cryptographic strength that would
//	 *                exceed the legal limits (as determined from the configured
//	 *                jurisdiction policy files).
//	 */
//	public final void init(int opmode, Key key, AlgorithmParameters params,
//			SecureRandom random) throws InvalidKeyException,
//			InvalidAlgorithmParameterException {
//		if (cipher != null) {
//			cipher.init(opmode, key, params, random);
//			return;
//		}
//		this.engineInit(opmode, key, params, random);
//	}
//
//	/**
//	 * Initializes this cipher with the public key from the given certificate.
//	 * <p>
//	 * The cipher is initialized for one of the following four operations:
//	 * encryption, decryption, key wrapping or key unwrapping, depending on the
//	 * value of <code>opmode</code>.
//	 * 
//	 * <p>
//	 * If the certificate is of type X.509 and has a <i>key usage</i> extension
//	 * field marked as critical, and the value of the <i>key usage</i> extension
//	 * field implies that the public key in the certificate and its
//	 * corresponding private key are not supposed to be used for the operation
//	 * represented by the value of <code>opmode</code>, an
//	 * <code>InvalidKeyException</code> is thrown.
//	 * 
//	 * <p>
//	 * If this cipher requires any algorithm parameters that cannot be derived
//	 * from the public key in the given certificate, the underlying cipher
//	 * implementation is supposed to generate the required parameters itself
//	 * (using provider-specific default or random values) if it is being
//	 * initialized for encryption or key wrapping, and raise an <code>
//	 * InvalidKeyException</code> if it is being initialized for decryption or
//	 * key unwrapping. The generated parameters can be retrieved using
//	 * {@link #getParameters() getParameters} or {@link #getIV() getIV} (if the
//	 * parameter is an IV).
//	 * 
//	 * <p>
//	 * If this cipher requires algorithm parameters that cannot be derived from
//	 * the input parameters, and there are no reasonable provider-specific
//	 * default values, initialization will necessarily fail.
//	 * 
//	 * <p>
//	 * If this cipher (including its underlying feedback or padding scheme)
//	 * requires any random bytes (e.g., for parameter generation), it will get
//	 * them using the <code>SecureRandom</code> implementation of the
//	 * highest-priority installed provider as the source of randomness. (If none
//	 * of the installed providers supply an implementation of SecureRandom, a
//	 * system-provided source of randomness will be used.)
//	 * 
//	 * <p>
//	 * Note that when a Cipher object is initialized, it loses all
//	 * previously-acquired state. In other words, initializing a Cipher is
//	 * equivalent to creating a new instance of that Cipher and initializing it.
//	 * 
//	 * @param opmode
//	 *            the operation mode of this cipher (this is one of the
//	 *            following: <code>ENCRYPT_MODE</code>,
//	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
//	 *            <code>UNWRAP_MODE</code>)
//	 * @param certificate
//	 *            the certificate
//	 * 
//	 * @exception InvalidKeyException
//	 *                if the public key in the given certificate is
//	 *                inappropriate for initializing this cipher, or this cipher
//	 *                requires algorithm parameters that cannot be determined
//	 *                from the public key in the given certificate, or the
//	 *                keysize of the public key in the given certificate has a
//	 *                keysize that exceeds the maximum allowable keysize (as
//	 *                determined by the configured jurisdiction policy files).
//	 */
//	public final void init(int opmode, Certificate certificate)
//			throws InvalidKeyException {
//		if (cipher != null) {
//			cipher.init(opmode, certificate);
//			return;
//		}
//		init(opmode, certificate, null);
//	}
//
//	// The OID for the KeyUsage extension in an X.509 v3 certificate
//	private static final String KEY_USAGE_EXTENSION_OID = "2.5.29.15";
//
//	/**
//	 * Initializes this cipher with the public key from the given certificate
//	 * and a source of randomness.
//	 * 
//	 * <p>
//	 * The cipher is initialized for one of the following four operations:
//	 * encryption, decryption, key wrapping or key unwrapping, depending on the
//	 * value of <code>opmode</code>.
//	 * 
//	 * <p>
//	 * If the certificate is of type X.509 and has a <i>key usage</i> extension
//	 * field marked as critical, and the value of the <i>key usage</i> extension
//	 * field implies that the public key in the certificate and its
//	 * corresponding private key are not supposed to be used for the operation
//	 * represented by the value of <code>opmode</code>, an
//	 * <code>InvalidKeyException</code> is thrown.
//	 * 
//	 * <p>
//	 * If this cipher requires any algorithm parameters that cannot be derived
//	 * from the public key in the given <code>certificate</code>, the underlying
//	 * cipher implementation is supposed to generate the required parameters
//	 * itself (using provider-specific default or random values) if it is being
//	 * initialized for encryption or key wrapping, and raise an
//	 * <code>InvalidKeyException</code> if it is being initialized for
//	 * decryption or key unwrapping. The generated parameters can be retrieved
//	 * using {@link #getParameters() getParameters} or {@link #getIV() getIV}
//	 * (if the parameter is an IV).
//	 * 
//	 * <p>
//	 * If this cipher requires algorithm parameters that cannot be derived from
//	 * the input parameters, and there are no reasonable provider-specific
//	 * default values, initialization will necessarily fail.
//	 * 
//	 * <p>
//	 * If this cipher (including its underlying feedback or padding scheme)
//	 * requires any random bytes (e.g., for parameter generation), it will get
//	 * them from <code>random</code>.
//	 * 
//	 * <p>
//	 * Note that when a Cipher object is initialized, it loses all
//	 * previously-acquired state. In other words, initializing a Cipher is
//	 * equivalent to creating a new instance of that Cipher and initializing it.
//	 * 
//	 * @param opmode
//	 *            the operation mode of this cipher (this is one of the
//	 *            following: <code>ENCRYPT_MODE</code>,
//	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
//	 *            <code>UNWRAP_MODE</code>)
//	 * @param certificate
//	 *            the certificate
//	 * @param random
//	 *            the source of randomness
//	 * 
//	 * @exception InvalidKeyException
//	 *                if the public key in the given certificate is
//	 *                inappropriate for initializing this cipher, or this cipher
//	 *                requires algorithm parameters that cannot be determined
//	 *                from the public key in the given certificate, or the
//	 *                keysize of the public key in the given certificate has a
//	 *                keysize that exceeds the maximum allowable keysize (as
//	 *                determined by the configured jurisdiction policy files).
//	 */
//	public final void init(int opmode, Certificate certificate,
//			SecureRandom random) throws InvalidKeyException {
//		if (cipher != null) {
//			cipher.init(opmode, certificate, random);
//			return;
//		}
//		// Check key usage if the certificate is of
//		// type X.509.
//		if (certificate instanceof java.security.cert.X509Certificate) {
//			// Check whether the cert has a key usage extension
//			// marked as a critical extension.
//			X509Certificate cert = (X509Certificate) certificate;
//			@SuppressWarnings("rawtypes")
//			Set critSet = cert.getCriticalExtensionOIDs();
//
//			if (critSet != null && !critSet.isEmpty()
//					&& critSet.contains(KEY_USAGE_EXTENSION_OID)) {
//				boolean[] keyUsageInfo = cert.getKeyUsage();
//				// keyUsageInfo[2] is for keyEncipherment;
//				// keyUsageInfo[3] is for dataEncipherment.
//				if ((keyUsageInfo != null)
//						&& (((opmode == Cipher.ENCRYPT_MODE)
//								&& (keyUsageInfo.length > 3) && (keyUsageInfo[3] == false)) || ((opmode == Cipher.WRAP_MODE)
//								&& (keyUsageInfo.length > 2) && (keyUsageInfo[2] == false)))) {
//					throw new InvalidKeyException("Wrong key usage");
//				}
//			}
//		}
//
//		PublicKey publicKey = (certificate == null ? null : certificate
//				.getPublicKey());
//
//		this.engineInit(opmode, publicKey, random);
//	}
//
//	/**
//	 * Continues a multiple-part encryption or decryption operation (depending
//	 * on how this cipher was initialized), processing another data part.
//	 * 
//	 * <p>
//	 * The bytes in the <code>input</code> buffer are processed, and the result
//	 * is stored in a new buffer.
//	 * 
//	 * <p>
//	 * If <code>input</code> has a length of zero, this method returns
//	 * <code>null</code>.
//	 * 
//	 * @param input
//	 *            the input buffer
//	 * 
//	 * @return the new buffer with the result, or null if the underlying cipher
//	 *         is a block cipher and the input data is too short to result in a
//	 *         new block.
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 */
//	public final byte[] update(byte[] input) {
//		if (cipher != null) {
//			return cipher.update(input);
//		}
//		// Input sanity check
//		if (input == null) {
//			throw new IllegalArgumentException("Null input buffer");
//		}
//
//		if (input.length == 0) {
//			return null;
//		}
//		return this.engineUpdate(input, 0, input.length);
//	}
//
//	/**
//	 * Continues a multiple-part encryption or decryption operation (depending
//	 * on how this cipher was initialized), processing another data part.
//	 * 
//	 * <p>
//	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
//	 * starting at <code>inputOffset</code> inclusive, are processed, and the
//	 * result is stored in a new buffer.
//	 * 
//	 * <p>
//	 * If <code>inputLen</code> is zero, this method returns <code>null</code>.
//	 * 
//	 * @param input
//	 *            the input buffer
//	 * @param inputOffset
//	 *            the offset in <code>input</code> where the input starts
//	 * @param inputLen
//	 *            the input length
//	 * 
//	 * @return the new buffer with the result, or null if the underlying cipher
//	 *         is a block cipher and the input data is too short to result in a
//	 *         new block.
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 */
//	public final byte[] update(byte[] input, int inputOffset, int inputLen) {
//		if (cipher != null) {
//			return cipher.update(input, inputOffset, inputLen);
//		}
//		// Input sanity check
//		if (input == null || inputOffset < 0
//				|| inputLen > (input.length - inputOffset) || inputLen < 0) {
//			throw new IllegalArgumentException("Bad arguments");
//		}
//
//		if (inputLen == 0) {
//			return null;
//		}
//		return this.engineUpdate(input, inputOffset, inputLen);
//	}
//
//	/**
//	 * Continues a multiple-part encryption or decryption operation (depending
//	 * on how this cipher was initialized), processing another data part.
//	 * 
//	 * <p>
//	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
//	 * starting at <code>inputOffset</code> inclusive, are processed, and the
//	 * result is stored in the <code>output</code> buffer.
//	 * 
//	 * <p>
//	 * If the <code>output</code> buffer is too small to hold the result, a
//	 * <code>ShortBufferException</code> is thrown. In this case, repeat this
//	 * call with a larger output buffer. Use {@link #getOutputSize(int)
//	 * getOutputSize} to determine how big the output buffer should be.
//	 * 
//	 * <p>
//	 * If <code>inputLen</code> is zero, this method returns a length of zero.
//	 * 
//	 * <p>
//	 * Note: this method should be copy-safe, which means the <code>input</code>
//	 * and <code>output</code> buffers can reference the same byte array and no
//	 * unprocessed input data is overwritten when the result is copied into the
//	 * output buffer.
//	 * 
//	 * @param input
//	 *            the input buffer
//	 * @param inputOffset
//	 *            the offset in <code>input</code> where the input starts
//	 * @param inputLen
//	 *            the input length
//	 * @param output
//	 *            the buffer for the result
//	 * 
//	 * @return the number of bytes stored in <code>output</code>
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 * @exception ShortBufferException
//	 *                if the given output buffer is too small to hold the result
//	 */
//	public final int update(byte[] input, int inputOffset, int inputLen,
//			byte[] output) throws ShortBufferException {
//		if (cipher != null) {
//			return cipher.update(input, inputOffset, inputLen, output);
//		}
//		// Input sanity check
//		if (input == null || inputOffset < 0
//				|| inputLen > (input.length - inputOffset) || inputLen < 0) {
//			throw new IllegalArgumentException("Bad arguments");
//		}
//
//		if (inputLen == 0) {
//			return 0;
//		}
//		return this.engineUpdate(input, inputOffset, inputLen, output, 0);
//	}
//
//	/**
//	 * Continues a multiple-part encryption or decryption operation (depending
//	 * on how this cipher was initialized), processing another data part.
//	 * 
//	 * <p>
//	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
//	 * starting at <code>inputOffset</code> inclusive, are processed, and the
//	 * result is stored in the <code>output</code> buffer, starting at
//	 * <code>outputOffset</code> inclusive.
//	 * 
//	 * <p>
//	 * If the <code>output</code> buffer is too small to hold the result, a
//	 * <code>ShortBufferException</code> is thrown. In this case, repeat this
//	 * call with a larger output buffer. Use {@link #getOutputSize(int)
//	 * getOutputSize} to determine how big the output buffer should be.
//	 * 
//	 * <p>
//	 * If <code>inputLen</code> is zero, this method returns a length of zero.
//	 * 
//	 * <p>
//	 * Note: this method should be copy-safe, which means the <code>input</code>
//	 * and <code>output</code> buffers can reference the same byte array and no
//	 * unprocessed input data is overwritten when the result is copied into the
//	 * output buffer.
//	 * 
//	 * @param input
//	 *            the input buffer
//	 * @param inputOffset
//	 *            the offset in <code>input</code> where the input starts
//	 * @param inputLen
//	 *            the input length
//	 * @param output
//	 *            the buffer for the result
//	 * @param outputOffset
//	 *            the offset in <code>output</code> where the result is stored
//	 * 
//	 * @return the number of bytes stored in <code>output</code>
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 * @exception ShortBufferException
//	 *                if the given output buffer is too small to hold the result
//	 */
//	public final int update(byte[] input, int inputOffset, int inputLen,
//			byte[] output, int outputOffset) throws ShortBufferException {
//
//		// Input sanity check
//		if (input == null || inputOffset < 0
//				|| inputLen > (input.length - inputOffset) || inputLen < 0
//				|| outputOffset < 0) {
//			throw new IllegalArgumentException("Bad arguments");
//		}
//
//		if (inputLen == 0) {
//			return 0;
//		}
//		return this.engineUpdate(input, inputOffset, inputLen, output,
//				outputOffset);
//	}
//
//	/**
//	 * Continues a multiple-part encryption or decryption operation (depending
//	 * on how this cipher was initialized), processing another data part.
//	 * 
//	 * <p>
//	 * All <code>input.remaining()</code> bytes starting at
//	 * <code>input.position()</code> are processed. The result is stored in the
//	 * output buffer. Upon return, the input buffer's position will be equal to
//	 * its limit; its limit will not have changed. The output buffer's position
//	 * will have advanced by n, where n is the value returned by this method;
//	 * the output buffer's limit will not have changed.
//	 * 
//	 * <p>
//	 * If <code>output.remaining()</code> bytes are insufficient to hold the
//	 * result, a <code>ShortBufferException</code> is thrown. In this case,
//	 * repeat this call with a larger output buffer. Use
//	 * {@link #getOutputSize(int) getOutputSize} to determine how big the output
//	 * buffer should be.
//	 * 
//	 * <p>
//	 * Note: this method should be copy-safe, which means the <code>input</code>
//	 * and <code>output</code> buffers can reference the same block of memory
//	 * and no unprocessed input data is overwritten when the result is copied
//	 * into the output buffer.
//	 * 
//	 * @param input
//	 *            the input ByteBuffer
//	 * @param output
//	 *            the output ByteByffer
//	 * 
//	 * @return the number of bytes stored in <code>output</code>
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 * @exception IllegalArgumentException
//	 *                if input and output are the same object
//	 * @exception ReadOnlyBufferException
//	 *                if the output buffer is read-only
//	 * @exception ShortBufferException
//	 *                if there is insufficient space in the output buffer
//	 * @since 1.5
//	 */
//	public final int update(ByteBuffer input, ByteBuffer output)
//			throws ShortBufferException {
//		if (cipher != null) {
//			return cipher.update(input, output);
//		}
//		if ((input == null) || (output == null)) {
//			throw new IllegalArgumentException("Buffers must not be null");
//		}
//		if (input == output) {
//			throw new IllegalArgumentException(
//					"Input and output buffers must "
//							+ "not be the same object, consider using buffer.duplicate()");
//		}
//		if (output.isReadOnly()) {
//			throw new ReadOnlyBufferException();
//		}
//
//		return this.engineUpdate(input, output);
//	}
//
//	/**
//	 * Finishes a multiple-part encryption or decryption operation, depending on
//	 * how this cipher was initialized.
//	 * 
//	 * <p>
//	 * Input data that may have been buffered during a previous
//	 * <code>update</code> operation is processed, with padding (if requested)
//	 * being applied. If an AEAD mode such as GCM/CCM is being used, the
//	 * authentication tag is appended in the case of encryption, or verified in
//	 * the case of decryption. The result is stored in a new buffer.
//	 * 
//	 * <p>
//	 * Upon finishing, this method resets this cipher object to the state it was
//	 * in when previously initialized via a call to <code>init</code>. That is,
//	 * the object is reset and available to encrypt or decrypt (depending on the
//	 * operation mode that was specified in the call to <code>init</code>) more
//	 * data.
//	 * 
//	 * <p>
//	 * Note: if any exception is thrown, this cipher object may need to be reset
//	 * before it can be used again.
//	 * 
//	 * @return the new buffer with the result
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 * @exception IllegalBlockSizeException
//	 *                if this cipher is a block cipher, no padding has been
//	 *                requested (only in encryption mode), and the total input
//	 *                length of the data processed by this cipher is not a
//	 *                multiple of block size; or if this encryption algorithm is
//	 *                unable to process the input data provided.
//	 * @exception BadPaddingException
//	 *                if this cipher is in decryption mode, and (un)padding has
//	 *                been requested, but the decrypted data is not bounded by
//	 *                the appropriate padding bytes
//	 * @exception AEADBadTagException
//	 *                if this cipher is decrypting in an AEAD mode (such as
//	 *                GCM/CCM), and the received authentication tag does not
//	 *                match the calculated value
//	 */
//	public final byte[] doFinal() throws IllegalBlockSizeException,
//			BadPaddingException {
//		if (cipher != null) {
//			return cipher.doFinal();
//		}
//		return this.engineDoFinal(new byte[0], 0, 0);
//	}
//
//	/**
//	 * Finishes a multiple-part encryption or decryption operation, depending on
//	 * how this cipher was initialized.
//	 * 
//	 * <p>
//	 * Input data that may have been buffered during a previous
//	 * <code>update</code> operation is processed, with padding (if requested)
//	 * being applied. If an AEAD mode such as GCM/CCM is being used, the
//	 * authentication tag is appended in the case of encryption, or verified in
//	 * the case of decryption. The result is stored in the <code>output</code>
//	 * buffer, starting at <code>outputOffset</code> inclusive.
//	 * 
//	 * <p>
//	 * If the <code>output</code> buffer is too small to hold the result, a
//	 * <code>ShortBufferException</code> is thrown. In this case, repeat this
//	 * call with a larger output buffer. Use {@link #getOutputSize(int)
//	 * getOutputSize} to determine how big the output buffer should be.
//	 * 
//	 * <p>
//	 * Upon finishing, this method resets this cipher object to the state it was
//	 * in when previously initialized via a call to <code>init</code>. That is,
//	 * the object is reset and available to encrypt or decrypt (depending on the
//	 * operation mode that was specified in the call to <code>init</code>) more
//	 * data.
//	 * 
//	 * <p>
//	 * Note: if any exception is thrown, this cipher object may need to be reset
//	 * before it can be used again.
//	 * 
//	 * @param output
//	 *            the buffer for the result
//	 * @param outputOffset
//	 *            the offset in <code>output</code> where the result is stored
//	 * 
//	 * @return the number of bytes stored in <code>output</code>
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 * @exception IllegalBlockSizeException
//	 *                if this cipher is a block cipher, no padding has been
//	 *                requested (only in encryption mode), and the total input
//	 *                length of the data processed by this cipher is not a
//	 *                multiple of block size; or if this encryption algorithm is
//	 *                unable to process the input data provided.
//	 * @exception ShortBufferException
//	 *                if the given output buffer is too small to hold the result
//	 * @exception BadPaddingException
//	 *                if this cipher is in decryption mode, and (un)padding has
//	 *                been requested, but the decrypted data is not bounded by
//	 *                the appropriate padding bytes
//	 * @exception AEADBadTagException
//	 *                if this cipher is decrypting in an AEAD mode (such as
//	 *                GCM/CCM), and the received authentication tag does not
//	 *                match the calculated value
//	 */
//	public final int doFinal(byte[] output, int outputOffset)
//			throws IllegalBlockSizeException, ShortBufferException,
//			BadPaddingException {
//		if (cipher != null) {
//			return cipher.doFinal(output, outputOffset);
//		}
//		// Input sanity check
//		if ((output == null) || (outputOffset < 0)) {
//			throw new IllegalArgumentException("Bad arguments");
//		}
//
//		return this.engineDoFinal(null, 0, 0, output, outputOffset);
//	}
//
//	/**
//	 * Encrypts or decrypts data in a single-part operation, or finishes a
//	 * multiple-part operation. The data is encrypted or decrypted, depending on
//	 * how this cipher was initialized.
//	 * 
//	 * <p>
//	 * The bytes in the <code>input</code> buffer, and any input bytes that may
//	 * have been buffered during a previous <code>update</code> operation, are
//	 * processed, with padding (if requested) being applied. If an AEAD mode
//	 * such as GCM/CCM is being used, the authentication tag is appended in the
//	 * case of encryption, or verified in the case of decryption. The result is
//	 * stored in a new buffer.
//	 * 
//	 * <p>
//	 * Upon finishing, this method resets this cipher object to the state it was
//	 * in when previously initialized via a call to <code>init</code>. That is,
//	 * the object is reset and available to encrypt or decrypt (depending on the
//	 * operation mode that was specified in the call to <code>init</code>) more
//	 * data.
//	 * 
//	 * <p>
//	 * Note: if any exception is thrown, this cipher object may need to be reset
//	 * before it can be used again.
//	 * 
//	 * @param input
//	 *            the input buffer
//	 * 
//	 * @return the new buffer with the result
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 * @exception IllegalBlockSizeException
//	 *                if this cipher is a block cipher, no padding has been
//	 *                requested (only in encryption mode), and the total input
//	 *                length of the data processed by this cipher is not a
//	 *                multiple of block size; or if this encryption algorithm is
//	 *                unable to process the input data provided.
//	 * @exception BadPaddingException
//	 *                if this cipher is in decryption mode, and (un)padding has
//	 *                been requested, but the decrypted data is not bounded by
//	 *                the appropriate padding bytes
//	 * @exception AEADBadTagException
//	 *                if this cipher is decrypting in an AEAD mode (such as
//	 *                GCM/CCM), and the received authentication tag does not
//	 *                match the calculated value
//	 */
//	public final byte[] doFinal(byte[] input) throws IllegalBlockSizeException,
//			BadPaddingException {
//		if (cipher != null) {
//			return cipher.doFinal(input);
//		}
//		// Input sanity check
//		if (input == null) {
//			throw new IllegalArgumentException("Null input buffer");
//		}
//
//		return this.engineDoFinal(input, 0, input.length);
//	}
//
//	/**
//	 * Encrypts or decrypts data in a single-part operation, or finishes a
//	 * multiple-part operation. The data is encrypted or decrypted, depending on
//	 * how this cipher was initialized.
//	 * 
//	 * <p>
//	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
//	 * starting at <code>inputOffset</code> inclusive, and any input bytes that
//	 * may have been buffered during a previous <code>update</code> operation,
//	 * are processed, with padding (if requested) being applied. If an AEAD mode
//	 * such as GCM/CCM is being used, the authentication tag is appended in the
//	 * case of encryption, or verified in the case of decryption. The result is
//	 * stored in a new buffer.
//	 * 
//	 * <p>
//	 * Upon finishing, this method resets this cipher object to the state it was
//	 * in when previously initialized via a call to <code>init</code>. That is,
//	 * the object is reset and available to encrypt or decrypt (depending on the
//	 * operation mode that was specified in the call to <code>init</code>) more
//	 * data.
//	 * 
//	 * <p>
//	 * Note: if any exception is thrown, this cipher object may need to be reset
//	 * before it can be used again.
//	 * 
//	 * @param input
//	 *            the input buffer
//	 * @param inputOffset
//	 *            the offset in <code>input</code> where the input starts
//	 * @param inputLen
//	 *            the input length
//	 * 
//	 * @return the new buffer with the result
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 * @exception IllegalBlockSizeException
//	 *                if this cipher is a block cipher, no padding has been
//	 *                requested (only in encryption mode), and the total input
//	 *                length of the data processed by this cipher is not a
//	 *                multiple of block size; or if this encryption algorithm is
//	 *                unable to process the input data provided.
//	 * @exception BadPaddingException
//	 *                if this cipher is in decryption mode, and (un)padding has
//	 *                been requested, but the decrypted data is not bounded by
//	 *                the appropriate padding bytes
//	 * @exception AEADBadTagException
//	 *                if this cipher is decrypting in an AEAD mode (such as
//	 *                GCM/CCM), and the received authentication tag does not
//	 *                match the calculated value
//	 */
//	public final byte[] doFinal(byte[] input, int inputOffset, int inputLen)
//			throws IllegalBlockSizeException, BadPaddingException {
//		if (cipher != null) {
//			return cipher.doFinal(input, inputOffset, inputLen);
//		}
//		// Input sanity check
//		if (input == null || inputOffset < 0
//				|| inputLen > (input.length - inputOffset) || inputLen < 0) {
//			throw new IllegalArgumentException("Bad arguments");
//		}
//
//		return this.engineDoFinal(input, inputOffset, inputLen);
//	}
//
//	/**
//	 * Encrypts or decrypts data in a single-part operation, or finishes a
//	 * multiple-part operation. The data is encrypted or decrypted, depending on
//	 * how this cipher was initialized.
//	 * 
//	 * <p>
//	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
//	 * starting at <code>inputOffset</code> inclusive, and any input bytes that
//	 * may have been buffered during a previous <code>update</code> operation,
//	 * are processed, with padding (if requested) being applied. If an AEAD mode
//	 * such as GCM/CCM is being used, the authentication tag is appended in the
//	 * case of encryption, or verified in the case of decryption. The result is
//	 * stored in the <code>output</code> buffer.
//	 * 
//	 * <p>
//	 * If the <code>output</code> buffer is too small to hold the result, a
//	 * <code>ShortBufferException</code> is thrown. In this case, repeat this
//	 * call with a larger output buffer. Use {@link #getOutputSize(int)
//	 * getOutputSize} to determine how big the output buffer should be.
//	 * 
//	 * <p>
//	 * Upon finishing, this method resets this cipher object to the state it was
//	 * in when previously initialized via a call to <code>init</code>. That is,
//	 * the object is reset and available to encrypt or decrypt (depending on the
//	 * operation mode that was specified in the call to <code>init</code>) more
//	 * data.
//	 * 
//	 * <p>
//	 * Note: if any exception is thrown, this cipher object may need to be reset
//	 * before it can be used again.
//	 * 
//	 * <p>
//	 * Note: this method should be copy-safe, which means the <code>input</code>
//	 * and <code>output</code> buffers can reference the same byte array and no
//	 * unprocessed input data is overwritten when the result is copied into the
//	 * output buffer.
//	 * 
//	 * @param input
//	 *            the input buffer
//	 * @param inputOffset
//	 *            the offset in <code>input</code> where the input starts
//	 * @param inputLen
//	 *            the input length
//	 * @param output
//	 *            the buffer for the result
//	 * 
//	 * @return the number of bytes stored in <code>output</code>
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 * @exception IllegalBlockSizeException
//	 *                if this cipher is a block cipher, no padding has been
//	 *                requested (only in encryption mode), and the total input
//	 *                length of the data processed by this cipher is not a
//	 *                multiple of block size; or if this encryption algorithm is
//	 *                unable to process the input data provided.
//	 * @exception ShortBufferException
//	 *                if the given output buffer is too small to hold the result
//	 * @exception BadPaddingException
//	 *                if this cipher is in decryption mode, and (un)padding has
//	 *                been requested, but the decrypted data is not bounded by
//	 *                the appropriate padding bytes
//	 * @exception AEADBadTagException
//	 *                if this cipher is decrypting in an AEAD mode (such as
//	 *                GCM/CCM), and the received authentication tag does not
//	 *                match the calculated value
//	 */
//	public final int doFinal(byte[] input, int inputOffset, int inputLen,
//			byte[] output) throws ShortBufferException,
//			IllegalBlockSizeException, BadPaddingException {
//		if (cipher != null) {
//			return cipher.doFinal(input, inputOffset, inputLen, output);
//		}
//		// Input sanity check
//		if (input == null || inputOffset < 0
//				|| inputLen > (input.length - inputOffset) || inputLen < 0) {
//			throw new IllegalArgumentException("Bad arguments");
//		}
//
//		return this.engineDoFinal(input, inputOffset, inputLen, output, 0);
//	}
//
//	/**
//	 * Encrypts or decrypts data in a single-part operation, or finishes a
//	 * multiple-part operation. The data is encrypted or decrypted, depending on
//	 * how this cipher was initialized.
//	 * 
//	 * <p>
//	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
//	 * starting at <code>inputOffset</code> inclusive, and any input bytes that
//	 * may have been buffered during a previous <code>update</code> operation,
//	 * are processed, with padding (if requested) being applied. If an AEAD mode
//	 * such as GCM/CCM is being used, the authentication tag is appended in the
//	 * case of encryption, or verified in the case of decryption. The result is
//	 * stored in the <code>output</code> buffer, starting at
//	 * <code>outputOffset</code> inclusive.
//	 * 
//	 * <p>
//	 * If the <code>output</code> buffer is too small to hold the result, a
//	 * <code>ShortBufferException</code> is thrown. In this case, repeat this
//	 * call with a larger output buffer. Use {@link #getOutputSize(int)
//	 * getOutputSize} to determine how big the output buffer should be.
//	 * 
//	 * <p>
//	 * Upon finishing, this method resets this cipher object to the state it was
//	 * in when previously initialized via a call to <code>init</code>. That is,
//	 * the object is reset and available to encrypt or decrypt (depending on the
//	 * operation mode that was specified in the call to <code>init</code>) more
//	 * data.
//	 * 
//	 * <p>
//	 * Note: if any exception is thrown, this cipher object may need to be reset
//	 * before it can be used again.
//	 * 
//	 * <p>
//	 * Note: this method should be copy-safe, which means the <code>input</code>
//	 * and <code>output</code> buffers can reference the same byte array and no
//	 * unprocessed input data is overwritten when the result is copied into the
//	 * output buffer.
//	 * 
//	 * @param input
//	 *            the input buffer
//	 * @param inputOffset
//	 *            the offset in <code>input</code> where the input starts
//	 * @param inputLen
//	 *            the input length
//	 * @param output
//	 *            the buffer for the result
//	 * @param outputOffset
//	 *            the offset in <code>output</code> where the result is stored
//	 * 
//	 * @return the number of bytes stored in <code>output</code>
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 * @exception IllegalBlockSizeException
//	 *                if this cipher is a block cipher, no padding has been
//	 *                requested (only in encryption mode), and the total input
//	 *                length of the data processed by this cipher is not a
//	 *                multiple of block size; or if this encryption algorithm is
//	 *                unable to process the input data provided.
//	 * @exception ShortBufferException
//	 *                if the given output buffer is too small to hold the result
//	 * @exception BadPaddingException
//	 *                if this cipher is in decryption mode, and (un)padding has
//	 *                been requested, but the decrypted data is not bounded by
//	 *                the appropriate padding bytes
//	 * @exception AEADBadTagException
//	 *                if this cipher is decrypting in an AEAD mode (such as
//	 *                GCM/CCM), and the received authentication tag does not
//	 *                match the calculated value
//	 */
//	public final int doFinal(byte[] input, int inputOffset, int inputLen,
//			byte[] output, int outputOffset) throws ShortBufferException,
//			IllegalBlockSizeException, BadPaddingException {
//		if (cipher != null) {
//			return cipher.doFinal(input, inputOffset, inputLen, output,
//					outputOffset);
//		}
//		// Input sanity check
//		if (input == null || inputOffset < 0
//				|| inputLen > (input.length - inputOffset) || inputLen < 0
//				|| outputOffset < 0) {
//			throw new IllegalArgumentException("Bad arguments");
//		}
//
//		return this.engineDoFinal(input, inputOffset, inputLen, output,
//				outputOffset);
//	}
//
//	/**
//	 * Encrypts or decrypts data in a single-part operation, or finishes a
//	 * multiple-part operation. The data is encrypted or decrypted, depending on
//	 * how this cipher was initialized.
//	 * 
//	 * <p>
//	 * All <code>input.remaining()</code> bytes starting at
//	 * <code>input.position()</code> are processed. If an AEAD mode such as
//	 * GCM/CCM is being used, the authentication tag is appended in the case of
//	 * encryption, or verified in the case of decryption. The result is stored
//	 * in the output buffer. Upon return, the input buffer's position will be
//	 * equal to its limit; its limit will not have changed. The output buffer's
//	 * position will have advanced by n, where n is the value returned by this
//	 * method; the output buffer's limit will not have changed.
//	 * 
//	 * <p>
//	 * If <code>output.remaining()</code> bytes are insufficient to hold the
//	 * result, a <code>ShortBufferException</code> is thrown. In this case,
//	 * repeat this call with a larger output buffer. Use
//	 * {@link #getOutputSize(int) getOutputSize} to determine how big the output
//	 * buffer should be.
//	 * 
//	 * <p>
//	 * Upon finishing, this method resets this cipher object to the state it was
//	 * in when previously initialized via a call to <code>init</code>. That is,
//	 * the object is reset and available to encrypt or decrypt (depending on the
//	 * operation mode that was specified in the call to <code>init</code>) more
//	 * data.
//	 * 
//	 * <p>
//	 * Note: if any exception is thrown, this cipher object may need to be reset
//	 * before it can be used again.
//	 * 
//	 * <p>
//	 * Note: this method should be copy-safe, which means the <code>input</code>
//	 * and <code>output</code> buffers can reference the same byte array and no
//	 * unprocessed input data is overwritten when the result is copied into the
//	 * output buffer.
//	 * 
//	 * @param input
//	 *            the input ByteBuffer
//	 * @param output
//	 *            the output ByteBuffer
//	 * 
//	 * @return the number of bytes stored in <code>output</code>
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized)
//	 * @exception IllegalArgumentException
//	 *                if input and output are the same object
//	 * @exception ReadOnlyBufferException
//	 *                if the output buffer is read-only
//	 * @exception IllegalBlockSizeException
//	 *                if this cipher is a block cipher, no padding has been
//	 *                requested (only in encryption mode), and the total input
//	 *                length of the data processed by this cipher is not a
//	 *                multiple of block size; or if this encryption algorithm is
//	 *                unable to process the input data provided.
//	 * @exception ShortBufferException
//	 *                if there is insufficient space in the output buffer
//	 * @exception BadPaddingException
//	 *                if this cipher is in decryption mode, and (un)padding has
//	 *                been requested, but the decrypted data is not bounded by
//	 *                the appropriate padding bytes
//	 * @exception AEADBadTagException
//	 *                if this cipher is decrypting in an AEAD mode (such as
//	 *                GCM/CCM), and the received authentication tag does not
//	 *                match the calculated value
//	 * 
//	 * @since 1.5
//	 */
//	public final int doFinal(ByteBuffer input, ByteBuffer output)
//			throws ShortBufferException, IllegalBlockSizeException,
//			BadPaddingException {
//		if (cipher != null) {
//			return cipher.doFinal(input, output);
//		}
//		if ((input == null) || (output == null)) {
//			throw new IllegalArgumentException("Buffers must not be null");
//		}
//		if (input == output) {
//			throw new IllegalArgumentException(
//					"Input and output buffers must "
//							+ "not be the same object, consider using buffer.duplicate()");
//		}
//		if (output.isReadOnly()) {
//			throw new ReadOnlyBufferException();
//		}
//
//		return this.engineDoFinal(input, output);
//	}
//
//	/**
//	 * Wrap a key.
//	 * 
//	 * @param key
//	 *            the key to be wrapped.
//	 * 
//	 * @return the wrapped key.
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized).
//	 * 
//	 * @exception IllegalBlockSizeException
//	 *                if this cipher is a block cipher, no padding has been
//	 *                requested, and the length of the encoding of the key to be
//	 *                wrapped is not a multiple of the block size.
//	 * 
//	 * @exception InvalidKeyException
//	 *                if it is impossible or unsafe to wrap the key with this
//	 *                cipher (e.g., a hardware protected key is being passed to
//	 *                a software-only cipher).
//	 */
//	public final byte[] wrap(Key key) throws IllegalBlockSizeException,
//			InvalidKeyException {
//		if (cipher != null) {
//			return cipher.wrap(key);
//		}
//		return this.engineWrap(key);
//	}
//
//	/**
//	 * Unwrap a previously wrapped key.
//	 * 
//	 * @param wrappedKey
//	 *            the key to be unwrapped.
//	 * 
//	 * @param wrappedKeyAlgorithm
//	 *            the algorithm associated with the wrapped key.
//	 * 
//	 * @param wrappedKeyType
//	 *            the type of the wrapped key. This must be one of
//	 *            <code>SECRET_KEY</code>, <code>PRIVATE_KEY</code>, or
//	 *            <code>PUBLIC_KEY</code>.
//	 * 
//	 * @return the unwrapped key.
//	 * 
//	 * @exception IllegalStateException
//	 *                if this cipher is in a wrong state (e.g., has not been
//	 *                initialized).
//	 * 
//	 * @exception NoSuchAlgorithmException
//	 *                if no installed providers can create keys of type
//	 *                <code>wrappedKeyType</code> for the
//	 *                <code>wrappedKeyAlgorithm</code>.
//	 * 
//	 * @exception InvalidKeyException
//	 *                if <code>wrappedKey</code> does not represent a wrapped
//	 *                key of type <code>wrappedKeyType</code> for the
//	 *                <code>wrappedKeyAlgorithm</code>.
//	 */
//	public final Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
//			int wrappedKeyType) throws InvalidKeyException,
//			NoSuchAlgorithmException {
//		if (cipher != null) {
//			return cipher.unwrap(wrappedKey, wrappedKeyAlgorithm,
//					wrappedKeyType);
//		}
//		if ((wrappedKeyType != Cipher.SECRET_KEY)
//				&& (wrappedKeyType != Cipher.PRIVATE_KEY)
//				&& (wrappedKeyType != Cipher.PUBLIC_KEY)) {
//			throw new InvalidParameterException("Invalid key type");
//		}
//
//		return this.engineUnwrap(wrappedKey, wrappedKeyAlgorithm,
//				wrappedKeyType);
//	}

}
