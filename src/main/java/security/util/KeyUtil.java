package security.util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Hex;

import common.Debug;
import security.ec.ECParameters;
import security.ec.NamedCurve;
import security.sm.SM2PublicKey;

public class KeyUtil {
	private static final Debug debug = Debug.getInstance("PKIUtil");

	public enum KeyType {
		PRIVATE, PUBLIC
	}

	public static Key convertKey(KeyType type, String algorithm, byte[] keyBuf)
			throws KeyException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		KeySpec keySpec;
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		Key key = null;
		if (KeyType.PRIVATE == type) {
			keySpec = new X509EncodedKeySpec(keyBuf);
			key = keyFactory.generatePrivate(keySpec);
		} else if (KeyType.PUBLIC == type) {
			keySpec = new PKCS8EncodedKeySpec(keyBuf);
			key = keyFactory.generatePublic(keySpec);
		} else {
			throw new KeyException("Key type is not supported.");
		}
		return key;
	}

	public static PublicKey convertRSAPublicKey(BigInteger modulus,
			BigInteger exponent) throws KeyException {
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
		KeyFactory kf;
		PublicKey publicKey = null;
		try {
			kf = KeyFactory.getInstance("RSA");
			publicKey = kf.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException e) {
			throw new KeyException("Invalid RSAPublicKey modulus.");
		} catch (InvalidKeySpecException e) {
			throw new KeyException("Invalid RSAPublicKey modulus or exponent.");
		}
		return publicKey;
	}

	public static PublicKey convertSM2PublicKey(byte[] params, byte[] point)
			throws KeyException {
		ECParameterSpec sm2Curve = NamedCurve.getECParameterSpec("SM2");
		PublicKey publicKey = null;
		ECPoint w;
		ECParameterSpec paramsSpec;
		try {
			paramsSpec = ECParameters.decodeParameters(params);
		} catch (IOException e) {
			String msg = e.getLocalizedMessage()
					+ "\n Can not decode Parameters: "
					+ Hex.encodeHexString(params) + "\n use SM2Parameters";
			debug.println(msg);
			paramsSpec = sm2Curve;
		}

		try {
			w = ECParameters.decodePoint(point, paramsSpec.getCurve());
		} catch (Exception localException) {
			throw new RuntimeException("Could not parse key values",
					localException);
		}
		try {
			publicKey = new SM2PublicKey(w, paramsSpec);
		} catch (InvalidKeyException e) {
			throw new KeyException(e);
		} catch (InvalidParameterSpecException e) {
			throw new KeyException(e);
		}
		return publicKey;

	}

	/**
	 * Creates a new secret key.
	 */
	public static SecretKey genSecretKey(String alias, String keyAlgName,
			int keysize, Provider p) throws Exception {
		KeyGenerator keygen;
		if (p != null) {
			keygen = KeyGenerator.getInstance(keyAlgName, p);
		} else {
			keygen = KeyGenerator.getInstance(keyAlgName);
		}
		if (keysize != -1) {
			keygen.init(keysize);
		} else if ("DES".equalsIgnoreCase(keyAlgName)) {
			keygen.init(56);
		} else if ("DESede".equalsIgnoreCase(keyAlgName)) {
			keygen.init(168);
		} else {
			throw new Exception(
					"Please provide keysize for secret key generation");
		}

		return keygen.generateKey();
	}

	/**
	 * Creates a new key pair
	 */
	public static KeyPair genKeyPair(String keyAlgName, int keysize, Provider p)
			throws Exception {
		if (keysize == -1) {
			if ("EC".equalsIgnoreCase(keyAlgName)) {
				keysize = 256;
			} else {
				keysize = 1024;
			}
		}
		KeyPairGenerator keyPairGen;
		if (p != null) {
			keyPairGen = KeyPairGenerator.getInstance(keyAlgName, p);
		} else {
			keyPairGen = KeyPairGenerator.getInstance(keyAlgName);
		}
		keyPairGen.initialize(keysize);
		return keyPairGen.generateKeyPair();
	}

	public static void checkKeySize(String algorithm, int keySize,
			AlgorithmParameterSpec params)
			throws InvalidAlgorithmParameterException {
		if (algorithm.equals("EC")) {
			if (keySize < 112) {
				throw new InvalidAlgorithmParameterException(
						"Key size must be at least 112 bit");
			}
			if (keySize > 2048) {
				// sanity check, nobody really wants keys this large
				throw new InvalidAlgorithmParameterException(
						"Key size must be at most 2048 bit");
			}
			return;
		} else if (algorithm.equals("RSA")) {
			BigInteger tmpExponent = RSAKeyGenParameterSpec.F4;
			if (params != null) {
				// Already tested for instanceof RSAKeyGenParameterSpec above
				tmpExponent = ((RSAKeyGenParameterSpec) params)
						.getPublicExponent();
			}
			try {
				// This provider supports 64K or less.
				int j = 512;
				int k = 64 * 1024;
				if (j > 0 && keySize < j)
					throw new InvalidKeyException((new StringBuffer())
							.append("RSA keys must be at least ").append(j)
							.append(" bits long").toString());
				int l = Math.min(k, 16384);
				if (keySize > l)
					throw new InvalidKeyException((new StringBuffer())
							.append("RSA keys must be no longer than ")
							.append(l).append(" bits").toString());
				if (tmpExponent != null && keySize > 3072
						&& tmpExponent.bitLength() > 64)
					throw new InvalidKeyException(
							"RSA exponents can be no longer than 64 bits  if modulus is greater than 3072 bits");
			} catch (InvalidKeyException e) {
				throw new InvalidAlgorithmParameterException(e.getMessage());
			}
			return;
		}

		if (keySize < 512) {
			throw new InvalidAlgorithmParameterException(
					"Key size must be at least 512 bit");
		}
		if (algorithm.equals("DH") && (params != null)) {
			// sanity check, nobody really wants keys this large
			if (keySize > 64 * 1024) {
				throw new InvalidAlgorithmParameterException(
						"Key size must be at most 65536 bit");
			}
		} else {
			// this restriction is in the spec for DSA
			// since we currently use DSA parameters for DH as well,
			// it also applies to DH if no parameters are specified
			if ((keySize > 1024) || ((keySize & 0x3f) != 0)) {
				throw new InvalidAlgorithmParameterException(
						"Key size must be a multiple of 64 and at most 1024 bit");
			}
		}
	}

}
