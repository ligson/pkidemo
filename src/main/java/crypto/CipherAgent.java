package crypto;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import security.sm.SM2Cipher;
import security.sm.SMS4Cipher;
import security.sm.TopSMProvider;

public final class CipherAgent {
	private final static Logger log = LoggerFactory.getLogger("TopCipherProxy");
	private final CipherSpi spi;
	private final Cipher cipher;

	private CipherAgent(Cipher cipher) {
		log.debug("#compatibility");
		log.debug("use JCE Cipher for " + cipher.getAlgorithm());
		this.cipher = cipher;
		this.spi = null;
	}

	private CipherAgent(CipherSpi spi) {
		this.cipher = null;
		this.spi = spi;
	}

	public static CipherAgent getInstance(String transformation)
			throws NoSuchAlgorithmException, NoSuchPaddingException {
		if (transformation.startsWith("SM2")) {
			return new CipherAgent(new SM2Cipher());
		} else if (transformation.startsWith("SMS4")) {
			return new CipherAgent(new SMS4Cipher());
		} else {
			return new CipherAgent(Cipher.getInstance(transformation));
		}
	}

	/**
	 * Returns the provider of this <code>Cipher</code> object.
	 * 
	 * @return the provider of this <code>Cipher</code> object
	 */
	public final Provider getProvider() {
		if (cipher != null) {
			return cipher.getProvider();
		}
		Provider provider = Security.getProvider(TopSMProvider.NAME);
		if (provider == null)
			provider = new TopSMProvider();
		return provider;
	}

	/**
	 * Returns the algorithm name of this <code>Cipher</code> object.
	 * 
	 * <p>
	 * This is the same name that was specified in one of the
	 * <code>getInstance</code> calls that created this <code>Cipher</code>
	 * object..
	 * 
	 * @return the algorithm name of this <code>Cipher</code> object.
	 */
	public final String getAlgorithm() {
		if (cipher != null) {
			return cipher.getAlgorithm();
		}
		return "SM2";
	}

	/**
	 * Returns the block size (in bytes).
	 * 
	 * @return the block size (in bytes), or 0 if the underlying algorithm is
	 *         not a block cipher
	 */
	public final int getBlockSize() {
		if (cipher != null) {
			return cipher.getBlockSize();
		}
		return (Integer) invokeSpi("engineGetBlockSize", null);
	}

	/**
	 * Returns the length in bytes that an output buffer would need to be in
	 * order to hold the result of the next <code>update</code> or
	 * <code>doFinal</code> operation, given the input length
	 * <code>inputLen</code> (in bytes).
	 * 
	 * <p>
	 * This call takes into account any unprocessed (buffered) data from a
	 * previous <code>update</code> call, padding, and AEAD tagging.
	 * 
	 * <p>
	 * The actual output length of the next <code>update</code> or
	 * <code>doFinal</code> call may be smaller than the length returned by this
	 * method.
	 * 
	 * @param inputLen
	 *            the input length (in bytes)
	 * 
	 * @return the required output buffer size (in bytes)
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not yet been
	 *                initialized)
	 */
	public final int getOutputSize(int inputLen) {
		if (cipher != null) {
			return cipher.getOutputSize(inputLen);
		}
		return (Integer) invokeSpi("engineGetOutputSize",
				new Class[] { int.class }, inputLen);
	}

	/**
	 * Returns the initialization vector (IV) in a new buffer.
	 * 
	 * <p>
	 * This is useful in the case where a random IV was created, or in the
	 * context of password-based encryption or decryption, where the IV is
	 * derived from a user-supplied password.
	 * 
	 * @return the initialization vector in a new buffer, or null if the
	 *         underlying algorithm does not use an IV, or if the IV has not yet
	 *         been set.
	 */
	public final byte[] getIV() {
		if (cipher != null) {
			return cipher.getIV();
		}
		return (byte[]) invokeSpi("engineGetIV", null);
	}

	/**
	 * Returns the parameters used with this cipher.
	 * 
	 * <p>
	 * The returned parameters may be the same that were used to initialize this
	 * cipher, or may contain a combination of default and random parameter
	 * values used by the underlying cipher implementation if this cipher
	 * requires algorithm parameters but was not initialized with any.
	 * 
	 * @return the parameters used with this cipher, or null if this cipher does
	 *         not use any parameters.
	 */
	public final AlgorithmParameters getParameters() {
		if (cipher != null) {
			return cipher.getParameters();
		}
		return (AlgorithmParameters) invokeSpi("engineGetParameters", null);
	}

	/**
	 * Initializes this cipher with a key.
	 * 
	 * <p>
	 * The cipher is initialized for one of the following four operations:
	 * encryption, decryption, key wrapping or key unwrapping, depending on the
	 * value of <code>opmode</code>.
	 * 
	 * <p>
	 * If this cipher requires any algorithm parameters that cannot be derived
	 * from the given <code>key</code>, the underlying cipher implementation is
	 * supposed to generate the required parameters itself (using
	 * provider-specific default or random values) if it is being initialized
	 * for encryption or key wrapping, and raise an
	 * <code>InvalidKeyException</code> if it is being initialized for
	 * decryption or key unwrapping. The generated parameters can be retrieved
	 * using {@link #getParameters() getParameters} or {@link #getIV() getIV}
	 * (if the parameter is an IV).
	 * 
	 * <p>
	 * If this cipher requires algorithm parameters that cannot be derived from
	 * the input parameters, and there are no reasonable provider-specific
	 * default values, initialization will necessarily fail.
	 * 
	 * <p>
	 * If this cipher (including its underlying feedback or padding scheme)
	 * requires any random bytes (e.g., for parameter generation), it will get
	 * them using the {@link SecureRandom <code>SecureRandom</code>}
	 * implementation of the highest-priority installed provider as the source
	 * of randomness. (If none of the installed providers supply an
	 * implementation of SecureRandom, a system-provided source of randomness
	 * will be used.)
	 * 
	 * <p>
	 * Note that when a Cipher object is initialized, it loses all
	 * previously-acquired state. In other words, initializing a Cipher is
	 * equivalent to creating a new instance of that Cipher and initializing it.
	 * 
	 * @param opmode
	 *            the operation mode of this cipher (this is one of the
	 *            following: <code>ENCRYPT_MODE</code>,
	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
	 *            <code>UNWRAP_MODE</code>)
	 * @param key
	 *            the key
	 * 
	 * @exception InvalidKeyException
	 *                if the given key is inappropriate for initializing this
	 *                cipher, or requires algorithm parameters that cannot be
	 *                determined from the given key, or if the given key has a
	 *                keysize that exceeds the maximum allowable keysize (as
	 *                determined from the configured jurisdiction policy files).
	 */
	public final void init(int opmode, Key key) throws InvalidKeyException {
		if (cipher != null) {
			cipher.init(opmode, key);
			return;
		}
		invokeSpi("engineInit", new Class[] { int.class, Key.class,
				SecureRandom.class }, opmode, key, null);
	}

	/**
	 * Initializes this cipher with a key and a source of randomness.
	 * 
	 * <p>
	 * The cipher is initialized for one of the following four operations:
	 * encryption, decryption, key wrapping or key unwrapping, depending on the
	 * value of <code>opmode</code>.
	 * 
	 * <p>
	 * If this cipher requires any algorithm parameters that cannot be derived
	 * from the given <code>key</code>, the underlying cipher implementation is
	 * supposed to generate the required parameters itself (using
	 * provider-specific default or random values) if it is being initialized
	 * for encryption or key wrapping, and raise an
	 * <code>InvalidKeyException</code> if it is being initialized for
	 * decryption or key unwrapping. The generated parameters can be retrieved
	 * using {@link #getParameters() getParameters} or {@link #getIV() getIV}
	 * (if the parameter is an IV).
	 * 
	 * <p>
	 * If this cipher requires algorithm parameters that cannot be derived from
	 * the input parameters, and there are no reasonable provider-specific
	 * default values, initialization will necessarily fail.
	 * 
	 * <p>
	 * If this cipher (including its underlying feedback or padding scheme)
	 * requires any random bytes (e.g., for parameter generation), it will get
	 * them from <code>random</code>.
	 * 
	 * <p>
	 * Note that when a Cipher object is initialized, it loses all
	 * previously-acquired state. In other words, initializing a Cipher is
	 * equivalent to creating a new instance of that Cipher and initializing it.
	 * 
	 * @param opmode
	 *            the operation mode of this cipher (this is one of the
	 *            following: <code>ENCRYPT_MODE</code>,
	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
	 *            <code>UNWRAP_MODE</code>)
	 * @param key
	 *            the encryption key
	 * @param random
	 *            the source of randomness
	 * 
	 * @exception InvalidKeyException
	 *                if the given key is inappropriate for initializing this
	 *                cipher, or requires algorithm parameters that cannot be
	 *                determined from the given key, or if the given key has a
	 *                keysize that exceeds the maximum allowable keysize (as
	 *                determined from the configured jurisdiction policy files).
	 */
	public final void init(int opmode, Key key, SecureRandom random)
			throws InvalidKeyException {
		if (cipher != null) {
			cipher.init(opmode, key, random);
			return;
		}
		invokeSpi("engineInit", new Class[] { int.class, Key.class,
				SecureRandom.class }, opmode, key, random);
	}

	/**
	 * Initializes this cipher with a key and a set of algorithm parameters.
	 * 
	 * <p>
	 * The cipher is initialized for one of the following four operations:
	 * encryption, decryption, key wrapping or key unwrapping, depending on the
	 * value of <code>opmode</code>.
	 * 
	 * <p>
	 * If this cipher requires any algorithm parameters and <code>params</code>
	 * is null, the underlying cipher implementation is supposed to generate the
	 * required parameters itself (using provider-specific default or random
	 * values) if it is being initialized for encryption or key wrapping, and
	 * raise an <code>InvalidAlgorithmParameterException</code> if it is being
	 * initialized for decryption or key unwrapping. The generated parameters
	 * can be retrieved using {@link #getParameters() getParameters} or
	 * {@link #getIV() getIV} (if the parameter is an IV).
	 * 
	 * <p>
	 * If this cipher requires algorithm parameters that cannot be derived from
	 * the input parameters, and there are no reasonable provider-specific
	 * default values, initialization will necessarily fail.
	 * 
	 * <p>
	 * If this cipher (including its underlying feedback or padding scheme)
	 * requires any random bytes (e.g., for parameter generation), it will get
	 * them using the {@link SecureRandom <code>SecureRandom</code>}
	 * implementation of the highest-priority installed provider as the source
	 * of randomness. (If none of the installed providers supply an
	 * implementation of SecureRandom, a system-provided source of randomness
	 * will be used.)
	 * 
	 * <p>
	 * Note that when a Cipher object is initialized, it loses all
	 * previously-acquired state. In other words, initializing a Cipher is
	 * equivalent to creating a new instance of that Cipher and initializing it.
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
	 * 
	 * @exception InvalidKeyException
	 *                if the given key is inappropriate for initializing this
	 *                cipher, or its keysize exceeds the maximum allowable
	 *                keysize (as determined from the configured jurisdiction
	 *                policy files).
	 * @exception InvalidAlgorithmParameterException
	 *                if the given algorithm parameters are inappropriate for
	 *                this cipher, or this cipher requires algorithm parameters
	 *                and <code>params</code> is null, or the given algorithm
	 *                parameters imply a cryptographic strength that would
	 *                exceed the legal limits (as determined from the configured
	 *                jurisdiction policy files).
	 */
	public final void init(int opmode, Key key, AlgorithmParameterSpec params)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		if (cipher != null) {
			cipher.init(opmode, key, params);
			return;
		}
		init(opmode, key, params, null);
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
	 * If this cipher requires any algorithm parameters and <code>params</code>
	 * is null, the underlying cipher implementation is supposed to generate the
	 * required parameters itself (using provider-specific default or random
	 * values) if it is being initialized for encryption or key wrapping, and
	 * raise an <code>InvalidAlgorithmParameterException</code> if it is being
	 * initialized for decryption or key unwrapping. The generated parameters
	 * can be retrieved using {@link #getParameters() getParameters} or
	 * {@link #getIV() getIV} (if the parameter is an IV).
	 * 
	 * <p>
	 * If this cipher requires algorithm parameters that cannot be derived from
	 * the input parameters, and there are no reasonable provider-specific
	 * default values, initialization will necessarily fail.
	 * 
	 * <p>
	 * If this cipher (including its underlying feedback or padding scheme)
	 * requires any random bytes (e.g., for parameter generation), it will get
	 * them from <code>random</code>.
	 * 
	 * <p>
	 * Note that when a Cipher object is initialized, it loses all
	 * previously-acquired state. In other words, initializing a Cipher is
	 * equivalent to creating a new instance of that Cipher and initializing it.
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
	 *                cipher, or its keysize exceeds the maximum allowable
	 *                keysize (as determined from the configured jurisdiction
	 *                policy files).
	 * @exception InvalidAlgorithmParameterException
	 *                if the given algorithm parameters are inappropriate for
	 *                this cipher, or this cipher requires algorithm parameters
	 *                and <code>params</code> is null, or the given algorithm
	 *                parameters imply a cryptographic strength that would
	 *                exceed the legal limits (as determined from the configured
	 *                jurisdiction policy files).
	 */
	public final void init(int opmode, Key key, AlgorithmParameterSpec params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		if (cipher != null) {
			cipher.init(opmode, key, params, random);
			return;
		}
		invokeSpi("engineInit", new Class[] { int.class, Key.class,
				AlgorithmParameterSpec.class, SecureRandom.class }, opmode,
				key, params, random);
	}

	/**
	 * Initializes this cipher with a key and a set of algorithm parameters.
	 * 
	 * <p>
	 * The cipher is initialized for one of the following four operations:
	 * encryption, decryption, key wrapping or key unwrapping, depending on the
	 * value of <code>opmode</code>.
	 * 
	 * <p>
	 * If this cipher requires any algorithm parameters and <code>params</code>
	 * is null, the underlying cipher implementation is supposed to generate the
	 * required parameters itself (using provider-specific default or random
	 * values) if it is being initialized for encryption or key wrapping, and
	 * raise an <code>InvalidAlgorithmParameterException</code> if it is being
	 * initialized for decryption or key unwrapping. The generated parameters
	 * can be retrieved using {@link #getParameters() getParameters} or
	 * {@link #getIV() getIV} (if the parameter is an IV).
	 * 
	 * <p>
	 * If this cipher requires algorithm parameters that cannot be derived from
	 * the input parameters, and there are no reasonable provider-specific
	 * default values, initialization will necessarily fail.
	 * 
	 * <p>
	 * If this cipher (including its underlying feedback or padding scheme)
	 * requires any random bytes (e.g., for parameter generation), it will get
	 * them using the {@link SecureRandom <code>SecureRandom</code>}
	 * implementation of the highest-priority installed provider as the source
	 * of randomness. (If none of the installed providers supply an
	 * implementation of SecureRandom, a system-provided source of randomness
	 * will be used.)
	 * 
	 * <p>
	 * Note that when a Cipher object is initialized, it loses all
	 * previously-acquired state. In other words, initializing a Cipher is
	 * equivalent to creating a new instance of that Cipher and initializing it.
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
	 * 
	 * @exception InvalidKeyException
	 *                if the given key is inappropriate for initializing this
	 *                cipher, or its keysize exceeds the maximum allowable
	 *                keysize (as determined from the configured jurisdiction
	 *                policy files).
	 * @exception InvalidAlgorithmParameterException
	 *                if the given algorithm parameters are inappropriate for
	 *                this cipher, or this cipher requires algorithm parameters
	 *                and <code>params</code> is null, or the given algorithm
	 *                parameters imply a cryptographic strength that would
	 *                exceed the legal limits (as determined from the configured
	 *                jurisdiction policy files).
	 */
	public final void init(int opmode, Key key, AlgorithmParameters params)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		if (cipher != null) {
			cipher.init(opmode, key, params);
			return;
		}
		init(opmode, key, params, null);
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
	 * If this cipher requires any algorithm parameters and <code>params</code>
	 * is null, the underlying cipher implementation is supposed to generate the
	 * required parameters itself (using provider-specific default or random
	 * values) if it is being initialized for encryption or key wrapping, and
	 * raise an <code>InvalidAlgorithmParameterException</code> if it is being
	 * initialized for decryption or key unwrapping. The generated parameters
	 * can be retrieved using {@link #getParameters() getParameters} or
	 * {@link #getIV() getIV} (if the parameter is an IV).
	 * 
	 * <p>
	 * If this cipher requires algorithm parameters that cannot be derived from
	 * the input parameters, and there are no reasonable provider-specific
	 * default values, initialization will necessarily fail.
	 * 
	 * <p>
	 * If this cipher (including its underlying feedback or padding scheme)
	 * requires any random bytes (e.g., for parameter generation), it will get
	 * them from <code>random</code>.
	 * 
	 * <p>
	 * Note that when a Cipher object is initialized, it loses all
	 * previously-acquired state. In other words, initializing a Cipher is
	 * equivalent to creating a new instance of that Cipher and initializing it.
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
	 *                cipher, or its keysize exceeds the maximum allowable
	 *                keysize (as determined from the configured jurisdiction
	 *                policy files).
	 * @exception InvalidAlgorithmParameterException
	 *                if the given algorithm parameters are inappropriate for
	 *                this cipher, or this cipher requires algorithm parameters
	 *                and <code>params</code> is null, or the given algorithm
	 *                parameters imply a cryptographic strength that would
	 *                exceed the legal limits (as determined from the configured
	 *                jurisdiction policy files).
	 */
	public final void init(int opmode, Key key, AlgorithmParameters params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		if (cipher != null) {
			cipher.init(opmode, key, params, random);
			return;
		}
		invokeSpi("engineInit", new Class[] { int.class, Key.class,
				AlgorithmParameters.class, SecureRandom.class }, opmode, key,
				params, random);
	}

	/**
	 * Initializes this cipher with the public key from the given certificate.
	 * <p>
	 * The cipher is initialized for one of the following four operations:
	 * encryption, decryption, key wrapping or key unwrapping, depending on the
	 * value of <code>opmode</code>.
	 * 
	 * <p>
	 * If the certificate is of type X.509 and has a <i>key usage</i> extension
	 * field marked as critical, and the value of the <i>key usage</i> extension
	 * field implies that the public key in the certificate and its
	 * corresponding private key are not supposed to be used for the operation
	 * represented by the value of <code>opmode</code>, an
	 * <code>InvalidKeyException</code> is thrown.
	 * 
	 * <p>
	 * If this cipher requires any algorithm parameters that cannot be derived
	 * from the public key in the given certificate, the underlying cipher
	 * implementation is supposed to generate the required parameters itself
	 * (using provider-specific default or random values) if it is being
	 * initialized for encryption or key wrapping, and raise an <code>
	 * InvalidKeyException</code> if it is being initialized for decryption or
	 * key unwrapping. The generated parameters can be retrieved using
	 * {@link #getParameters() getParameters} or {@link #getIV() getIV} (if the
	 * parameter is an IV).
	 * 
	 * <p>
	 * If this cipher requires algorithm parameters that cannot be derived from
	 * the input parameters, and there are no reasonable provider-specific
	 * default values, initialization will necessarily fail.
	 * 
	 * <p>
	 * If this cipher (including its underlying feedback or padding scheme)
	 * requires any random bytes (e.g., for parameter generation), it will get
	 * them using the <code>SecureRandom</code> implementation of the
	 * highest-priority installed provider as the source of randomness. (If none
	 * of the installed providers supply an implementation of SecureRandom, a
	 * system-provided source of randomness will be used.)
	 * 
	 * <p>
	 * Note that when a Cipher object is initialized, it loses all
	 * previously-acquired state. In other words, initializing a Cipher is
	 * equivalent to creating a new instance of that Cipher and initializing it.
	 * 
	 * @param opmode
	 *            the operation mode of this cipher (this is one of the
	 *            following: <code>ENCRYPT_MODE</code>,
	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
	 *            <code>UNWRAP_MODE</code>)
	 * @param certificate
	 *            the certificate
	 * 
	 * @exception InvalidKeyException
	 *                if the public key in the given certificate is
	 *                inappropriate for initializing this cipher, or this cipher
	 *                requires algorithm parameters that cannot be determined
	 *                from the public key in the given certificate, or the
	 *                keysize of the public key in the given certificate has a
	 *                keysize that exceeds the maximum allowable keysize (as
	 *                determined by the configured jurisdiction policy files).
	 */
	public final void init(int opmode, Certificate certificate)
			throws InvalidKeyException {
		if (cipher != null) {
			cipher.init(opmode, certificate);
			return;
		}
		init(opmode, certificate, null);
	}

	// The OID for the KeyUsage extension in an X.509 v3 certificate
	private static final String KEY_USAGE_EXTENSION_OID = "2.5.29.15";

	/**
	 * Initializes this cipher with the public key from the given certificate
	 * and a source of randomness.
	 * 
	 * <p>
	 * The cipher is initialized for one of the following four operations:
	 * encryption, decryption, key wrapping or key unwrapping, depending on the
	 * value of <code>opmode</code>.
	 * 
	 * <p>
	 * If the certificate is of type X.509 and has a <i>key usage</i> extension
	 * field marked as critical, and the value of the <i>key usage</i> extension
	 * field implies that the public key in the certificate and its
	 * corresponding private key are not supposed to be used for the operation
	 * represented by the value of <code>opmode</code>, an
	 * <code>InvalidKeyException</code> is thrown.
	 * 
	 * <p>
	 * If this cipher requires any algorithm parameters that cannot be derived
	 * from the public key in the given <code>certificate</code>, the underlying
	 * cipher implementation is supposed to generate the required parameters
	 * itself (using provider-specific default or random values) if it is being
	 * initialized for encryption or key wrapping, and raise an
	 * <code>InvalidKeyException</code> if it is being initialized for
	 * decryption or key unwrapping. The generated parameters can be retrieved
	 * using {@link #getParameters() getParameters} or {@link #getIV() getIV}
	 * (if the parameter is an IV).
	 * 
	 * <p>
	 * If this cipher requires algorithm parameters that cannot be derived from
	 * the input parameters, and there are no reasonable provider-specific
	 * default values, initialization will necessarily fail.
	 * 
	 * <p>
	 * If this cipher (including its underlying feedback or padding scheme)
	 * requires any random bytes (e.g., for parameter generation), it will get
	 * them from <code>random</code>.
	 * 
	 * <p>
	 * Note that when a Cipher object is initialized, it loses all
	 * previously-acquired state. In other words, initializing a Cipher is
	 * equivalent to creating a new instance of that Cipher and initializing it.
	 * 
	 * @param opmode
	 *            the operation mode of this cipher (this is one of the
	 *            following: <code>ENCRYPT_MODE</code>,
	 *            <code>DECRYPT_MODE</code>, <code>WRAP_MODE</code> or
	 *            <code>UNWRAP_MODE</code>)
	 * @param certificate
	 *            the certificate
	 * @param random
	 *            the source of randomness
	 * 
	 * @exception InvalidKeyException
	 *                if the public key in the given certificate is
	 *                inappropriate for initializing this cipher, or this cipher
	 *                requires algorithm parameters that cannot be determined
	 *                from the public key in the given certificate, or the
	 *                keysize of the public key in the given certificate has a
	 *                keysize that exceeds the maximum allowable keysize (as
	 *                determined by the configured jurisdiction policy files).
	 */
	public final void init(int opmode, Certificate certificate,
			SecureRandom random) throws InvalidKeyException {
		if (cipher != null) {
			cipher.init(opmode, certificate, random);
			return;
		}
		// Check key usage if the certificate is of
		// type X.509.
		if (certificate instanceof X509Certificate) {
			// Check whether the cert has a key usage extension
			// marked as a critical extension.
			X509Certificate cert = (X509Certificate) certificate;
			@SuppressWarnings("rawtypes")
			Set critSet = cert.getCriticalExtensionOIDs();

			if (critSet != null && !critSet.isEmpty()
					&& critSet.contains(KEY_USAGE_EXTENSION_OID)) {
				boolean[] keyUsageInfo = cert.getKeyUsage();
				// keyUsageInfo[2] is for keyEncipherment;
				// keyUsageInfo[3] is for dataEncipherment.
				if ((keyUsageInfo != null)
						&& (((opmode == Cipher.ENCRYPT_MODE)
								&& (keyUsageInfo.length > 3) && (keyUsageInfo[3] == false)) || ((opmode == Cipher.WRAP_MODE)
								&& (keyUsageInfo.length > 2) && (keyUsageInfo[2] == false)))) {
					throw new InvalidKeyException("Wrong key usage");
				}
			}
		}

		PublicKey publicKey = (certificate == null ? null : certificate
				.getPublicKey());
		invokeSpi("engineInit", new Class[] { int.class, Key.class,
				SecureRandom.class }, opmode, publicKey, random);
	}

	/**
	 * Continues a multiple-part encryption or decryption operation (depending
	 * on how this cipher was initialized), processing another data part.
	 * 
	 * <p>
	 * The bytes in the <code>input</code> buffer are processed, and the result
	 * is stored in a new buffer.
	 * 
	 * <p>
	 * If <code>input</code> has a length of zero, this method returns
	 * <code>null</code>.
	 * 
	 * @param input
	 *            the input buffer
	 * 
	 * @return the new buffer with the result, or null if the underlying cipher
	 *         is a block cipher and the input data is too short to result in a
	 *         new block.
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 */
	public final byte[] update(byte[] input) {
		if (cipher != null) {
			return cipher.update(input);
		}
		// Input sanity check
		if (input == null) {
			throw new IllegalArgumentException("Null input buffer");
		}

		if (input.length == 0) {
			return null;
		}
		return (byte[]) invokeSpi("engineUpdate", new Class[] { byte[].class,
				int.class, int.class }, input, 0, input.length);
	}

	/**
	 * Continues a multiple-part encryption or decryption operation (depending
	 * on how this cipher was initialized), processing another data part.
	 * 
	 * <p>
	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
	 * starting at <code>inputOffset</code> inclusive, are processed, and the
	 * result is stored in a new buffer.
	 * 
	 * <p>
	 * If <code>inputLen</code> is zero, this method returns <code>null</code>.
	 * 
	 * @param input
	 *            the input buffer
	 * @param inputOffset
	 *            the offset in <code>input</code> where the input starts
	 * @param inputLen
	 *            the input length
	 * 
	 * @return the new buffer with the result, or null if the underlying cipher
	 *         is a block cipher and the input data is too short to result in a
	 *         new block.
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 */
	public final byte[] update(byte[] input, int inputOffset, int inputLen) {
		if (cipher != null) {
			return cipher.update(input, inputOffset, inputLen);
		}
		// Input sanity check
		if (input == null || inputOffset < 0
				|| inputLen > (input.length - inputOffset) || inputLen < 0) {
			throw new IllegalArgumentException("Bad arguments");
		}

		if (inputLen == 0) {
			return null;
		}
		return (byte[]) invokeSpi("engineUpdate", new Class[] { byte[].class,
				int.class, int.class }, input, inputOffset, inputLen);
	}

	/**
	 * Continues a multiple-part encryption or decryption operation (depending
	 * on how this cipher was initialized), processing another data part.
	 * 
	 * <p>
	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
	 * starting at <code>inputOffset</code> inclusive, are processed, and the
	 * result is stored in the <code>output</code> buffer.
	 * 
	 * <p>
	 * If the <code>output</code> buffer is too small to hold the result, a
	 * <code>ShortBufferException</code> is thrown. In this case, repeat this
	 * call with a larger output buffer. Use {@link #getOutputSize(int)
	 * getOutputSize} to determine how big the output buffer should be.
	 * 
	 * <p>
	 * If <code>inputLen</code> is zero, this method returns a length of zero.
	 * 
	 * <p>
	 * Note: this method should be copy-safe, which means the <code>input</code>
	 * and <code>output</code> buffers can reference the same byte array and no
	 * unprocessed input data is overwritten when the result is copied into the
	 * output buffer.
	 * 
	 * @param input
	 *            the input buffer
	 * @param inputOffset
	 *            the offset in <code>input</code> where the input starts
	 * @param inputLen
	 *            the input length
	 * @param output
	 *            the buffer for the result
	 * 
	 * @return the number of bytes stored in <code>output</code>
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 * @exception ShortBufferException
	 *                if the given output buffer is too small to hold the result
	 */
	public final int update(byte[] input, int inputOffset, int inputLen,
			byte[] output) throws ShortBufferException {
		if (cipher != null) {
			return cipher.update(input, inputOffset, inputLen, output);
		}
		// Input sanity check
		if (input == null || inputOffset < 0
				|| inputLen > (input.length - inputOffset) || inputLen < 0) {
			throw new IllegalArgumentException("Bad arguments");
		}

		if (inputLen == 0) {
			return 0;
		}
		return (Integer) invokeSpi("engineUpdate", new Class[] { byte[].class,
				int.class, int.class, byte[].class, int.class }, input,
				inputOffset, inputLen, output, 0);
	}

	/**
	 * Continues a multiple-part encryption or decryption operation (depending
	 * on how this cipher was initialized), processing another data part.
	 * 
	 * <p>
	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
	 * starting at <code>inputOffset</code> inclusive, are processed, and the
	 * result is stored in the <code>output</code> buffer, starting at
	 * <code>outputOffset</code> inclusive.
	 * 
	 * <p>
	 * If the <code>output</code> buffer is too small to hold the result, a
	 * <code>ShortBufferException</code> is thrown. In this case, repeat this
	 * call with a larger output buffer. Use {@link #getOutputSize(int)
	 * getOutputSize} to determine how big the output buffer should be.
	 * 
	 * <p>
	 * If <code>inputLen</code> is zero, this method returns a length of zero.
	 * 
	 * <p>
	 * Note: this method should be copy-safe, which means the <code>input</code>
	 * and <code>output</code> buffers can reference the same byte array and no
	 * unprocessed input data is overwritten when the result is copied into the
	 * output buffer.
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
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 * @exception ShortBufferException
	 *                if the given output buffer is too small to hold the result
	 */
	public final int update(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException {

		// Input sanity check
		if (input == null || inputOffset < 0
				|| inputLen > (input.length - inputOffset) || inputLen < 0
				|| outputOffset < 0) {
			throw new IllegalArgumentException("Bad arguments");
		}

		if (inputLen == 0) {
			return 0;
		}
		return (Integer) invokeSpi("engineUpdate", new Class[] { byte[].class,
				int.class, int.class, byte[].class, int.class }, input,
				inputOffset, inputLen, output, outputOffset);
	}

	/**
	 * Continues a multiple-part encryption or decryption operation (depending
	 * on how this cipher was initialized), processing another data part.
	 * 
	 * <p>
	 * All <code>input.remaining()</code> bytes starting at
	 * <code>input.position()</code> are processed. The result is stored in the
	 * output buffer. Upon return, the input buffer's position will be equal to
	 * its limit; its limit will not have changed. The output buffer's position
	 * will have advanced by n, where n is the value returned by this method;
	 * the output buffer's limit will not have changed.
	 * 
	 * <p>
	 * If <code>output.remaining()</code> bytes are insufficient to hold the
	 * result, a <code>ShortBufferException</code> is thrown. In this case,
	 * repeat this call with a larger output buffer. Use
	 * {@link #getOutputSize(int) getOutputSize} to determine how big the output
	 * buffer should be.
	 * 
	 * <p>
	 * Note: this method should be copy-safe, which means the <code>input</code>
	 * and <code>output</code> buffers can reference the same block of memory
	 * and no unprocessed input data is overwritten when the result is copied
	 * into the output buffer.
	 * 
	 * @param input
	 *            the input ByteBuffer
	 * @param output
	 *            the output ByteByffer
	 * 
	 * @return the number of bytes stored in <code>output</code>
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 * @exception IllegalArgumentException
	 *                if input and output are the same object
	 * @exception ReadOnlyBufferException
	 *                if the output buffer is read-only
	 * @exception ShortBufferException
	 *                if there is insufficient space in the output buffer
	 * @since 1.5
	 */
	public final int update(ByteBuffer input, ByteBuffer output)
			throws ShortBufferException {
		if (cipher != null) {
			return cipher.update(input, output);
		}
		if ((input == null) || (output == null)) {
			throw new IllegalArgumentException("Buffers must not be null");
		}
		if (input == output) {
			throw new IllegalArgumentException(
					"Input and output buffers must "
							+ "not be the same object, consider using buffer.duplicate()");
		}
		if (output.isReadOnly()) {
			throw new ReadOnlyBufferException();
		}

		return (Integer) invokeSpi("engineUpdate", new Class[] {
				ByteBuffer.class, ByteBuffer.class }, input, output);
	}

	/**
	 * Finishes a multiple-part encryption or decryption operation, depending on
	 * how this cipher was initialized.
	 * 
	 * <p>
	 * Input data that may have been buffered during a previous
	 * <code>update</code> operation is processed, with padding (if requested)
	 * being applied. If an AEAD mode such as GCM/CCM is being used, the
	 * authentication tag is appended in the case of encryption, or verified in
	 * the case of decryption. The result is stored in a new buffer.
	 * 
	 * <p>
	 * Upon finishing, this method resets this cipher object to the state it was
	 * in when previously initialized via a call to <code>init</code>. That is,
	 * the object is reset and available to encrypt or decrypt (depending on the
	 * operation mode that was specified in the call to <code>init</code>) more
	 * data.
	 * 
	 * <p>
	 * Note: if any exception is thrown, this cipher object may need to be reset
	 * before it can be used again.
	 * 
	 * @return the new buffer with the result
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 * @exception IllegalBlockSizeException
	 *                if this cipher is a block cipher, no padding has been
	 *                requested (only in encryption mode), and the total input
	 *                length of the data processed by this cipher is not a
	 *                multiple of block size; or if this encryption algorithm is
	 *                unable to process the input data provided.
	 * @exception BadPaddingException
	 *                if this cipher is in decryption mode, and (un)padding has
	 *                been requested, but the decrypted data is not bounded by
	 *                the appropriate padding bytes
	 * @exception AEADBadTagException
	 *                if this cipher is decrypting in an AEAD mode (such as
	 *                GCM/CCM), and the received authentication tag does not
	 *                match the calculated value
	 */
	public final byte[] doFinal() throws IllegalBlockSizeException,
			BadPaddingException {
		if (cipher != null) {
			return cipher.doFinal();
		}
		return (byte[]) invokeSpi("engineDoFinal", new Class[] { byte[].class,
				int.class, int.class }, new byte[0], 0, 0);
	}

	/**
	 * Finishes a multiple-part encryption or decryption operation, depending on
	 * how this cipher was initialized.
	 * 
	 * <p>
	 * Input data that may have been buffered during a previous
	 * <code>update</code> operation is processed, with padding (if requested)
	 * being applied. If an AEAD mode such as GCM/CCM is being used, the
	 * authentication tag is appended in the case of encryption, or verified in
	 * the case of decryption. The result is stored in the <code>output</code>
	 * buffer, starting at <code>outputOffset</code> inclusive.
	 * 
	 * <p>
	 * If the <code>output</code> buffer is too small to hold the result, a
	 * <code>ShortBufferException</code> is thrown. In this case, repeat this
	 * call with a larger output buffer. Use {@link #getOutputSize(int)
	 * getOutputSize} to determine how big the output buffer should be.
	 * 
	 * <p>
	 * Upon finishing, this method resets this cipher object to the state it was
	 * in when previously initialized via a call to <code>init</code>. That is,
	 * the object is reset and available to encrypt or decrypt (depending on the
	 * operation mode that was specified in the call to <code>init</code>) more
	 * data.
	 * 
	 * <p>
	 * Note: if any exception is thrown, this cipher object may need to be reset
	 * before it can be used again.
	 * 
	 * @param output
	 *            the buffer for the result
	 * @param outputOffset
	 *            the offset in <code>output</code> where the result is stored
	 * 
	 * @return the number of bytes stored in <code>output</code>
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 * @exception IllegalBlockSizeException
	 *                if this cipher is a block cipher, no padding has been
	 *                requested (only in encryption mode), and the total input
	 *                length of the data processed by this cipher is not a
	 *                multiple of block size; or if this encryption algorithm is
	 *                unable to process the input data provided.
	 * @exception ShortBufferException
	 *                if the given output buffer is too small to hold the result
	 * @exception BadPaddingException
	 *                if this cipher is in decryption mode, and (un)padding has
	 *                been requested, but the decrypted data is not bounded by
	 *                the appropriate padding bytes
	 * @exception AEADBadTagException
	 *                if this cipher is decrypting in an AEAD mode (such as
	 *                GCM/CCM), and the received authentication tag does not
	 *                match the calculated value
	 */
	public final int doFinal(byte[] output, int outputOffset)
			throws IllegalBlockSizeException, ShortBufferException,
			BadPaddingException {
		if (cipher != null) {
			return cipher.doFinal(output, outputOffset);
		}
		// Input sanity check
		if ((output == null) || (outputOffset < 0)) {
			throw new IllegalArgumentException("Bad arguments");
		}

		return (Integer) invokeSpi("engineDoFinal", new Class[] { byte[].class,
				int.class, int.class, byte[].class, int.class }, null, 0, 0,
				output, outputOffset);
	}

	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a
	 * multiple-part operation. The data is encrypted or decrypted, depending on
	 * how this cipher was initialized.
	 * 
	 * <p>
	 * The bytes in the <code>input</code> buffer, and any input bytes that may
	 * have been buffered during a previous <code>update</code> operation, are
	 * processed, with padding (if requested) being applied. If an AEAD mode
	 * such as GCM/CCM is being used, the authentication tag is appended in the
	 * case of encryption, or verified in the case of decryption. The result is
	 * stored in a new buffer.
	 * 
	 * <p>
	 * Upon finishing, this method resets this cipher object to the state it was
	 * in when previously initialized via a call to <code>init</code>. That is,
	 * the object is reset and available to encrypt or decrypt (depending on the
	 * operation mode that was specified in the call to <code>init</code>) more
	 * data.
	 * 
	 * <p>
	 * Note: if any exception is thrown, this cipher object may need to be reset
	 * before it can be used again.
	 * 
	 * @param input
	 *            the input buffer
	 * 
	 * @return the new buffer with the result
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 * @exception IllegalBlockSizeException
	 *                if this cipher is a block cipher, no padding has been
	 *                requested (only in encryption mode), and the total input
	 *                length of the data processed by this cipher is not a
	 *                multiple of block size; or if this encryption algorithm is
	 *                unable to process the input data provided.
	 * @exception BadPaddingException
	 *                if this cipher is in decryption mode, and (un)padding has
	 *                been requested, but the decrypted data is not bounded by
	 *                the appropriate padding bytes
	 * @exception AEADBadTagException
	 *                if this cipher is decrypting in an AEAD mode (such as
	 *                GCM/CCM), and the received authentication tag does not
	 *                match the calculated value
	 */
	public final byte[] doFinal(byte[] input) throws IllegalBlockSizeException,
			BadPaddingException {
		if (cipher != null) {
			return cipher.doFinal(input);
		}
		return (byte[]) invokeSpi("engineDoFinal", new Class[] { byte[].class,
				int.class, int.class }, input, 0, input.length);
	}

	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a
	 * multiple-part operation. The data is encrypted or decrypted, depending on
	 * how this cipher was initialized.
	 * 
	 * <p>
	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
	 * starting at <code>inputOffset</code> inclusive, and any input bytes that
	 * may have been buffered during a previous <code>update</code> operation,
	 * are processed, with padding (if requested) being applied. If an AEAD mode
	 * such as GCM/CCM is being used, the authentication tag is appended in the
	 * case of encryption, or verified in the case of decryption. The result is
	 * stored in a new buffer.
	 * 
	 * <p>
	 * Upon finishing, this method resets this cipher object to the state it was
	 * in when previously initialized via a call to <code>init</code>. That is,
	 * the object is reset and available to encrypt or decrypt (depending on the
	 * operation mode that was specified in the call to <code>init</code>) more
	 * data.
	 * 
	 * <p>
	 * Note: if any exception is thrown, this cipher object may need to be reset
	 * before it can be used again.
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
	 * @exception IllegalBlockSizeException
	 *                if this cipher is a block cipher, no padding has been
	 *                requested (only in encryption mode), and the total input
	 *                length of the data processed by this cipher is not a
	 *                multiple of block size; or if this encryption algorithm is
	 *                unable to process the input data provided.
	 * @exception BadPaddingException
	 *                if this cipher is in decryption mode, and (un)padding has
	 *                been requested, but the decrypted data is not bounded by
	 *                the appropriate padding bytes
	 * @exception AEADBadTagException
	 *                if this cipher is decrypting in an AEAD mode (such as
	 *                GCM/CCM), and the received authentication tag does not
	 *                match the calculated value
	 */
	public final byte[] doFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {
		if (cipher != null) {
			return cipher.doFinal(input, inputOffset, inputLen);
		}
		// Input sanity check
		if (input == null || inputOffset < 0
				|| inputLen > (input.length - inputOffset) || inputLen < 0) {
			throw new IllegalArgumentException("Bad arguments");
		}

		return (byte[]) invokeSpi("engineDoFinal", new Class[] { byte[].class,
				int.class, int.class }, input, inputOffset, inputLen);
	}

	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a
	 * multiple-part operation. The data is encrypted or decrypted, depending on
	 * how this cipher was initialized.
	 * 
	 * <p>
	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
	 * starting at <code>inputOffset</code> inclusive, and any input bytes that
	 * may have been buffered during a previous <code>update</code> operation,
	 * are processed, with padding (if requested) being applied. If an AEAD mode
	 * such as GCM/CCM is being used, the authentication tag is appended in the
	 * case of encryption, or verified in the case of decryption. The result is
	 * stored in the <code>output</code> buffer.
	 * 
	 * <p>
	 * If the <code>output</code> buffer is too small to hold the result, a
	 * <code>ShortBufferException</code> is thrown. In this case, repeat this
	 * call with a larger output buffer. Use {@link #getOutputSize(int)
	 * getOutputSize} to determine how big the output buffer should be.
	 * 
	 * <p>
	 * Upon finishing, this method resets this cipher object to the state it was
	 * in when previously initialized via a call to <code>init</code>. That is,
	 * the object is reset and available to encrypt or decrypt (depending on the
	 * operation mode that was specified in the call to <code>init</code>) more
	 * data.
	 * 
	 * <p>
	 * Note: if any exception is thrown, this cipher object may need to be reset
	 * before it can be used again.
	 * 
	 * <p>
	 * Note: this method should be copy-safe, which means the <code>input</code>
	 * and <code>output</code> buffers can reference the same byte array and no
	 * unprocessed input data is overwritten when the result is copied into the
	 * output buffer.
	 * 
	 * @param input
	 *            the input buffer
	 * @param inputOffset
	 *            the offset in <code>input</code> where the input starts
	 * @param inputLen
	 *            the input length
	 * @param output
	 *            the buffer for the result
	 * 
	 * @return the number of bytes stored in <code>output</code>
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 * @exception IllegalBlockSizeException
	 *                if this cipher is a block cipher, no padding has been
	 *                requested (only in encryption mode), and the total input
	 *                length of the data processed by this cipher is not a
	 *                multiple of block size; or if this encryption algorithm is
	 *                unable to process the input data provided.
	 * @exception ShortBufferException
	 *                if the given output buffer is too small to hold the result
	 * @exception BadPaddingException
	 *                if this cipher is in decryption mode, and (un)padding has
	 *                been requested, but the decrypted data is not bounded by
	 *                the appropriate padding bytes
	 * @exception AEADBadTagException
	 *                if this cipher is decrypting in an AEAD mode (such as
	 *                GCM/CCM), and the received authentication tag does not
	 *                match the calculated value
	 */
	public final int doFinal(byte[] input, int inputOffset, int inputLen,
			byte[] output) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {
		if (cipher != null) {
			return cipher.doFinal(input, inputOffset, inputLen, output);
		}
		// Input sanity check
		if (input == null || inputOffset < 0
				|| inputLen > (input.length - inputOffset) || inputLen < 0) {
			throw new IllegalArgumentException("Bad arguments");
		}

		return (Integer) invokeSpi("engineDoFinal", new Class[] { byte[].class,
				int.class, int.class, byte[].class, int.class }, input,
				inputOffset, inputLen, output, 0);
	}

	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a
	 * multiple-part operation. The data is encrypted or decrypted, depending on
	 * how this cipher was initialized.
	 * 
	 * <p>
	 * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
	 * starting at <code>inputOffset</code> inclusive, and any input bytes that
	 * may have been buffered during a previous <code>update</code> operation,
	 * are processed, with padding (if requested) being applied. If an AEAD mode
	 * such as GCM/CCM is being used, the authentication tag is appended in the
	 * case of encryption, or verified in the case of decryption. The result is
	 * stored in the <code>output</code> buffer, starting at
	 * <code>outputOffset</code> inclusive.
	 * 
	 * <p>
	 * If the <code>output</code> buffer is too small to hold the result, a
	 * <code>ShortBufferException</code> is thrown. In this case, repeat this
	 * call with a larger output buffer. Use {@link #getOutputSize(int)
	 * getOutputSize} to determine how big the output buffer should be.
	 * 
	 * <p>
	 * Upon finishing, this method resets this cipher object to the state it was
	 * in when previously initialized via a call to <code>init</code>. That is,
	 * the object is reset and available to encrypt or decrypt (depending on the
	 * operation mode that was specified in the call to <code>init</code>) more
	 * data.
	 * 
	 * <p>
	 * Note: if any exception is thrown, this cipher object may need to be reset
	 * before it can be used again.
	 * 
	 * <p>
	 * Note: this method should be copy-safe, which means the <code>input</code>
	 * and <code>output</code> buffers can reference the same byte array and no
	 * unprocessed input data is overwritten when the result is copied into the
	 * output buffer.
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
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 * @exception IllegalBlockSizeException
	 *                if this cipher is a block cipher, no padding has been
	 *                requested (only in encryption mode), and the total input
	 *                length of the data processed by this cipher is not a
	 *                multiple of block size; or if this encryption algorithm is
	 *                unable to process the input data provided.
	 * @exception ShortBufferException
	 *                if the given output buffer is too small to hold the result
	 * @exception BadPaddingException
	 *                if this cipher is in decryption mode, and (un)padding has
	 *                been requested, but the decrypted data is not bounded by
	 *                the appropriate padding bytes
	 * @exception AEADBadTagException
	 *                if this cipher is decrypting in an AEAD mode (such as
	 *                GCM/CCM), and the received authentication tag does not
	 *                match the calculated value
	 */
	public final int doFinal(byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset) throws ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {
		if (cipher != null) {
			return cipher.doFinal(input, inputOffset, inputLen, output,
					outputOffset);
		}
		// Input sanity check
		if (input == null || inputOffset < 0
				|| inputLen > (input.length - inputOffset) || inputLen < 0
				|| outputOffset < 0) {
			throw new IllegalArgumentException("Bad arguments");
		}

		return (Integer) invokeSpi("engineDoFinal", new Class[] { byte[].class,
				int.class, int.class, byte[].class, int.class }, input,
				inputOffset, inputLen, output, outputOffset);
	}

	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a
	 * multiple-part operation. The data is encrypted or decrypted, depending on
	 * how this cipher was initialized.
	 * 
	 * <p>
	 * All <code>input.remaining()</code> bytes starting at
	 * <code>input.position()</code> are processed. If an AEAD mode such as
	 * GCM/CCM is being used, the authentication tag is appended in the case of
	 * encryption, or verified in the case of decryption. The result is stored
	 * in the output buffer. Upon return, the input buffer's position will be
	 * equal to its limit; its limit will not have changed. The output buffer's
	 * position will have advanced by n, where n is the value returned by this
	 * method; the output buffer's limit will not have changed.
	 * 
	 * <p>
	 * If <code>output.remaining()</code> bytes are insufficient to hold the
	 * result, a <code>ShortBufferException</code> is thrown. In this case,
	 * repeat this call with a larger output buffer. Use
	 * {@link #getOutputSize(int) getOutputSize} to determine how big the output
	 * buffer should be.
	 * 
	 * <p>
	 * Upon finishing, this method resets this cipher object to the state it was
	 * in when previously initialized via a call to <code>init</code>. That is,
	 * the object is reset and available to encrypt or decrypt (depending on the
	 * operation mode that was specified in the call to <code>init</code>) more
	 * data.
	 * 
	 * <p>
	 * Note: if any exception is thrown, this cipher object may need to be reset
	 * before it can be used again.
	 * 
	 * <p>
	 * Note: this method should be copy-safe, which means the <code>input</code>
	 * and <code>output</code> buffers can reference the same byte array and no
	 * unprocessed input data is overwritten when the result is copied into the
	 * output buffer.
	 * 
	 * @param input
	 *            the input ByteBuffer
	 * @param output
	 *            the output ByteBuffer
	 * 
	 * @return the number of bytes stored in <code>output</code>
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized)
	 * @exception IllegalArgumentException
	 *                if input and output are the same object
	 * @exception ReadOnlyBufferException
	 *                if the output buffer is read-only
	 * @exception IllegalBlockSizeException
	 *                if this cipher is a block cipher, no padding has been
	 *                requested (only in encryption mode), and the total input
	 *                length of the data processed by this cipher is not a
	 *                multiple of block size; or if this encryption algorithm is
	 *                unable to process the input data provided.
	 * @exception ShortBufferException
	 *                if there is insufficient space in the output buffer
	 * @exception BadPaddingException
	 *                if this cipher is in decryption mode, and (un)padding has
	 *                been requested, but the decrypted data is not bounded by
	 *                the appropriate padding bytes
	 * @exception AEADBadTagException
	 *                if this cipher is decrypting in an AEAD mode (such as
	 *                GCM/CCM), and the received authentication tag does not
	 *                match the calculated value
	 * 
	 * @since 1.5
	 */
	public final int doFinal(ByteBuffer input, ByteBuffer output)
			throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {
		if (cipher != null) {
			return cipher.doFinal(input, output);
		}
		if ((input == null) || (output == null)) {
			throw new IllegalArgumentException("Buffers must not be null");
		}
		if (input == output) {
			throw new IllegalArgumentException(
					"Input and output buffers must "
							+ "not be the same object, consider using buffer.duplicate()");
		}
		if (output.isReadOnly()) {
			throw new ReadOnlyBufferException();
		}
		return (Integer) invokeSpi("engineDoFinal", new Class[] {
				ByteBuffer.class, ByteBuffer.class }, input, output);
	}

	/**
	 * Wrap a key.
	 * 
	 * @param key
	 *            the key to be wrapped.
	 * 
	 * @return the wrapped key.
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized).
	 * 
	 * @exception IllegalBlockSizeException
	 *                if this cipher is a block cipher, no padding has been
	 *                requested, and the length of the encoding of the key to be
	 *                wrapped is not a multiple of the block size.
	 * 
	 * @exception InvalidKeyException
	 *                if it is impossible or unsafe to wrap the key with this
	 *                cipher (e.g., a hardware protected key is being passed to
	 *                a software-only cipher).
	 */
	public final byte[] wrap(Key key) throws IllegalBlockSizeException,
			InvalidKeyException {
		if (cipher != null) {
			return cipher.wrap(key);
		}
		return (byte[]) invokeSpi("engineWrap", new Class[] { Key.class }, key);
	}

	/**
	 * Unwrap a previously wrapped key.
	 * 
	 * @param wrappedKey
	 *            the key to be unwrapped.
	 * 
	 * @param wrappedKeyAlgorithm
	 *            the algorithm associated with the wrapped key.
	 * 
	 * @param wrappedKeyType
	 *            the type of the wrapped key. This must be one of
	 *            <code>SECRET_KEY</code>, <code>PRIVATE_KEY</code>, or
	 *            <code>PUBLIC_KEY</code>.
	 * 
	 * @return the unwrapped key.
	 * 
	 * @exception IllegalStateException
	 *                if this cipher is in a wrong state (e.g., has not been
	 *                initialized).
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
	public final Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
			int wrappedKeyType) throws InvalidKeyException,
			NoSuchAlgorithmException {
		if (cipher != null) {
			return cipher.unwrap(wrappedKey, wrappedKeyAlgorithm,
					wrappedKeyType);
		}
		if ((wrappedKeyType != Cipher.SECRET_KEY)
				&& (wrappedKeyType != Cipher.PRIVATE_KEY)
				&& (wrappedKeyType != Cipher.PUBLIC_KEY)) {
			throw new InvalidParameterException("Invalid key type");
		}

		return (Key) invokeSpi("engineUnwrap", new Class[] { byte[].class,
				String.class, int.class }, wrappedKey, wrappedKeyAlgorithm,
				wrappedKeyType);
	}

	private Object invokeSpi(String methodName, Class<?>[] parameterTypes,
			Object... args) {
		try {
			Method method = this.spi.getClass().getDeclaredMethod(methodName,
					parameterTypes);
			method.setAccessible(true);
			return method.invoke(this.spi, args);
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (NoSuchMethodException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			e.printStackTrace();
		}
		return null;
	}

}
