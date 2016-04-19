package security.sm;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class SM2KeyFactory extends KeyFactorySpi {
	public static final KeyFactory INSTANCE;
	public static final Provider sm2InternalProvider;

	public static ECKey toSM2Key(Key paramKey) throws InvalidKeyException {
		if (paramKey instanceof ECKey) {
			ECKey sm2Key = (ECKey) paramKey;
			checkKey(sm2Key);
			return sm2Key;
		}
		return ((ECKey) INSTANCE.translateKey(paramKey));
	}

	private static void checkKey(ECKey sm2Key) throws InvalidKeyException {
		if (sm2Key instanceof ECPublicKey) {
			if (sm2Key instanceof SM2PublicKey)
				return;
		} else if (sm2Key instanceof ECPrivateKey) {
			if (sm2Key instanceof SM2PrivateKey)
				return;
		} else {
			throw new InvalidKeyException("Neither a public nor a private key");
		}

		String str = ((Key) sm2Key).getAlgorithm();
		if (!(str.equals("SM2")))
			throw new InvalidKeyException("Not an SM2 key: " + str);
	}

	protected Key engineTranslateKey(Key paramKey) throws InvalidKeyException {
		if (paramKey == null) {
			throw new InvalidKeyException("Key must not be null");
		}
		String str = paramKey.getAlgorithm();
		if (!(str.equals("SM2"))) {
			throw new InvalidKeyException("Not an SM2 key: " + str);
		}
		if (paramKey instanceof PublicKey)
			try {
				return implTranslatePublicKey((PublicKey) paramKey);
			} catch (InvalidParameterSpecException e) {
				throw new InvalidKeyException(e);
			}
		if (paramKey instanceof PrivateKey) {
			return implTranslatePrivateKey((PrivateKey) paramKey);
		}
		throw new InvalidKeyException("Neither a public nor a private key");
	}

	protected PublicKey engineGeneratePublic(KeySpec paramKeySpec)
			throws InvalidKeySpecException {
		try {
			return implGeneratePublic(paramKeySpec);
		} catch (InvalidKeySpecException localInvalidKeySpecException) {
			throw localInvalidKeySpecException;
		} catch (GeneralSecurityException localGeneralSecurityException) {
			throw new InvalidKeySpecException(localGeneralSecurityException);
		}
	}

	protected PrivateKey engineGeneratePrivate(KeySpec paramKeySpec)
			throws InvalidKeySpecException {
		try {
			return implGeneratePrivate(paramKeySpec);
		} catch (InvalidKeySpecException localInvalidKeySpecException) {
			throw localInvalidKeySpecException;
		} catch (GeneralSecurityException localGeneralSecurityException) {
			throw new InvalidKeySpecException(localGeneralSecurityException);
		}
	}

	private PublicKey implTranslatePublicKey(PublicKey paramPublicKey)
			throws InvalidKeyException, InvalidParameterSpecException {
		Object localObject;
		if (paramPublicKey instanceof ECPublicKey) {
			if (paramPublicKey instanceof SM2PublicKey) {
				return paramPublicKey;
			}
			localObject = (ECPublicKey) paramPublicKey;
			return new SM2PublicKey(((ECPublicKey) localObject).getW(),
					((ECPublicKey) localObject).getParams());
		}

		if ("X.509".equals(paramPublicKey.getFormat())) {
			byte[] publicKeyBuf = paramPublicKey.getEncoded();
			return new SM2PublicKey(publicKeyBuf);
		}
		throw new InvalidKeyException(
				"Public keys must be instance of ECPublicKey or have X.509 encoding");
	}

	private PrivateKey implTranslatePrivateKey(PrivateKey paramPrivateKey)
			throws InvalidKeyException {
		if (paramPrivateKey instanceof ECPrivateKey) {
			if (paramPrivateKey instanceof SM2PrivateKey) {
				return paramPrivateKey;
			}
			ECPrivateKey localECPrivateKey = (ECPrivateKey) paramPrivateKey;
			try {
				return new SM2PrivateKey(localECPrivateKey.getS(),
						localECPrivateKey.getParams());
			} catch (InvalidParameterSpecException e) {
				throw new InvalidKeyException(e);
			}
		}

		if ("PKCS#8".equals(paramPrivateKey.getFormat())) {
			return new SM2PrivateKey(paramPrivateKey.getEncoded());
		}
		throw new InvalidKeyException(
				"Private keys must be instance of ECPrivateKey or have PKCS#8 encoding");
	}

	private PublicKey implGeneratePublic(KeySpec paramKeySpec)
			throws GeneralSecurityException {
		Object localObject;
		if (paramKeySpec instanceof X509EncodedKeySpec) {
			localObject = (X509EncodedKeySpec) paramKeySpec;
			return new SM2PublicKey(
					((X509EncodedKeySpec) localObject).getEncoded());
		}
		if (paramKeySpec instanceof ECPublicKeySpec) {
			localObject = (ECPublicKeySpec) paramKeySpec;
			return new SM2PublicKey(((ECPublicKeySpec) localObject).getW(),
					((ECPublicKeySpec) localObject).getParams());
		}

		throw new InvalidKeySpecException(
				"Only ECPublicKeySpec and X509EncodedKeySpec supported for SM2 public keys");
	}

	private PrivateKey implGeneratePrivate(KeySpec keySpec)
			throws GeneralSecurityException {
		Object _obj;
		if (keySpec instanceof PKCS8EncodedKeySpec) {
			_obj = (PKCS8EncodedKeySpec) keySpec;
			return new SM2PrivateKey(
					((PKCS8EncodedKeySpec) _obj).getEncoded());
		}
		if (keySpec instanceof ECPrivateKeySpec) {
			_obj = (ECPrivateKeySpec) keySpec;
			return new SM2PrivateKey(((ECPrivateKeySpec) _obj).getS(),
					((ECPrivateKeySpec) _obj).getParams());
		}
		throw new InvalidKeySpecException(
				"Only ECPrivateKeySpec and PKCS8EncodedKeySpec supported for EC private keys");
	}

	@SuppressWarnings("unchecked")
	protected <T extends KeySpec> T engineGetKeySpec(Key key,
			Class<T> paramClass) throws InvalidKeySpecException {
		try {
			key = engineTranslateKey(key);
		} catch (InvalidKeyException localInvalidKeyException) {
			throw new InvalidKeySpecException(localInvalidKeyException);
		}
		Object _obj;
		if (key instanceof ECPublicKey) {
			_obj = (ECPublicKey) key;
			if (ECPublicKeySpec.class.isAssignableFrom(paramClass)) {
				return (T) new ECPublicKeySpec(
						((ECPublicKey) _obj).getW(),
						((ECPublicKey) _obj).getParams());
			}

			if (X509EncodedKeySpec.class.isAssignableFrom(paramClass)) {
				return (T) new X509EncodedKeySpec(key.getEncoded());
			}
			throw new InvalidKeySpecException(
					"KeySpec must be ECPublicKeySpec or X509EncodedKeySpec for EC public keys");
		}

		if (key instanceof ECPrivateKey) {
			if (PKCS8EncodedKeySpec.class.isAssignableFrom(paramClass))
				return (T) new PKCS8EncodedKeySpec(key.getEncoded());
			if (ECPrivateKeySpec.class.isAssignableFrom(paramClass)) {
				_obj = (ECPrivateKey) key;
				return (T) new ECPrivateKeySpec(
						((ECPrivateKey) _obj).getS(),
						((ECPrivateKey) _obj).getParams());
			}

			throw new InvalidKeySpecException(
					"KeySpec must be ECPrivateKeySpec or PKCS8EncodedKeySpec for EC private keys");
		}

		throw new InvalidKeySpecException("Neither public nor private key");
	}

	static {
		final Provider provider = new TopSMProvider();
		try {
			INSTANCE = KeyFactory.getInstance("SM2", provider);
		} catch (NoSuchAlgorithmException localNoSuchAlgorithmException) {
			throw new RuntimeException(localNoSuchAlgorithmException);
		}
		sm2InternalProvider = provider;
	}
}
