package security.rsa;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import security.util.DerInputStream;
import security.util.DerValue;
import pkiutil.DataUtil;

public class RSAKeyUtil {
    public final static int MIN_MODLEN = 512;
    public final static int MAX_MODLEN = 16384;

    /*
     * If the modulus length is above this value, restrict the size of the
     * exponent to something that can be reasonably computed. We could simply
     * hardcode the exp len to something like 64 bits, but this approach allows
     * flexibility in case impls would like to use larger module and exponent
     * values.
     */
    public final static int MAX_MODLEN_RESTRICT_EXP = 3072;
    public final static int MAX_RESTRICTED_EXPLEN = 64;

    private static final boolean restrictExpLen = true;

    public static void checkKeyLengths(int modulusLen, BigInteger exponent,
	    int minModulusLen, int maxModulusLen) throws InvalidKeyException {

	if ((minModulusLen > 0) && (modulusLen < (minModulusLen))) {
	    throw new InvalidKeyException("RSA keys must be at least "
		    + minModulusLen + " bits long");
	}

	// Even though our policy file may allow this, we don't want
	// either value (mod/exp) to be too big.

	int maxLen = Math.min(maxModulusLen, MAX_MODLEN);

	// If a RSAPrivateKey/RSAPublicKey, make sure the
	// modulus len isn't too big.
	if (modulusLen > maxLen) {
	    throw new InvalidKeyException("RSA keys must be no longer than "
		    + maxLen + " bits");
	}

	// If a RSAPublicKey, make sure the exponent isn't too big.
	if (restrictExpLen && (exponent != null)
		&& (modulusLen > MAX_MODLEN_RESTRICT_EXP)
		&& (exponent.bitLength() > MAX_RESTRICTED_EXPLEN)) {
	    throw new InvalidKeyException(
		    "RSA exponents can be no longer than "
			    + MAX_RESTRICTED_EXPLEN + " bits "
			    + " if modulus is greater than "
			    + MAX_MODLEN_RESTRICT_EXP + " bits");
	}
    }

    public static PrivateKey translatePrivateKey(Key key) {
	try {
	    if (key instanceof RSAPrivateKey) {
		return (PrivateKey) key;
	    } else if ("X.509".equals(key.getFormat())) {
		key = KeyFactory.getInstance("RSA").translateKey(key);
		return (PrivateKey) key;
	    } else {
		throw new InvalidKeyException("PublicKey must be instance "
			+ "of RSAPublicKey or have X.509 encoding");
	    }

	} catch (Exception e) {
	    throw new RuntimeException(
		    "can not be happend , translate RSAKey fail!", e);
	}
    }

    public static PublicKey translatePublic(Key key) {
	try {
	    if (key instanceof RSAPublicKey) {
		return (PublicKey) key;
	    } else if ("X.509".equals(key.getFormat())) {
		key = (PublicKey) KeyFactory.getInstance("RSA").translateKey(
			key);
		return (PublicKey) key;
	    } else {
		throw new InvalidKeyException("PublicKey must be instance "
			+ "of RSAPublicKey or have X.509 encoding");
	    }
	} catch (NoSuchAlgorithmException e) {
	    throw new RuntimeException(
		    "can not be happened, but RSA KeyFactory not support.", e);
	} catch (InvalidKeyException e) {
	    throw new RuntimeException("can not be happened, but...", e);
	}
    }

    public static PrivateKey generatePrivate(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof PKCS8EncodedKeySpec) {
	    byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
	    PrivateKey privateKey = null;
	    try {
		privateKey = decodePrivate(encoded);
	    } catch (InvalidKeyException e) {
		throw new RuntimeException("decodePrivateKey fail!", e);
	    }
	    return translatePrivateKey(privateKey);
	} else if (keySpec instanceof RSAPrivateKeySpec) {
	    try {
		return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
	    } catch (NoSuchAlgorithmException ex) {
		throw new RuntimeException(
			"can not be happened, but RSA KeyFactory not support.",
			ex);
	    }
	} else {
	    throw new InvalidKeySpecException("Only RSAPrivateKeySpec and "
		    + "PKCS8EncodedKeySpec supported for RSA public keys");
	}
    }

    public static PrivateKey decodePrivate(InputStream in)
	    throws InvalidKeyException {
	try {
	    DerValue privateKeyInfo = new DerValue(in);
	    if (privateKeyInfo.tag != 48) {
		throw new InvalidKeyException("invalid key format");
	    }
	    BigInteger version = privateKeyInfo.data.getBigInteger();
	    if (!(version.equals(BigInteger.ZERO))) {
		throw new IOException("version mismatch: (supported: "
			+ BigInteger.ZERO.toString(16) + ", parsed: "
			+ version.toString(16));
	    }
	    privateKeyInfo.data.getDerValue(); // read Algorithm ID
	    DerInputStream key = new DerInputStream(
		    privateKeyInfo.data.getOctetString());
	    DerValue derValue = key.getDerValue();
	    if (derValue.tag != DerValue.tag_Sequence) {
		throw new IOException("Not a SEQUENCE");
	    }
	    DerInputStream data = derValue.data;
	    // read version, must be zero
	    BigInteger v = readPositiveBigInteger(data);
	    BigInteger n = readPositiveBigInteger(data);
	    BigInteger e = readPositiveBigInteger(data); // read e
	    BigInteger d = readPositiveBigInteger(data);
	    BigInteger p = readPositiveBigInteger(data); // read p
	    BigInteger q = readPositiveBigInteger(data); // read q
	    BigInteger pe = readPositiveBigInteger(data); // read pe
	    BigInteger qe = readPositiveBigInteger(data); // read qe
	    BigInteger coeff = readPositiveBigInteger(data); // read coeff
	    if (data.available() != 0)
		throw new InvalidKeyException("Extra key data");
	    return generatePrivateKey(v, n, e, d, p, q, pe, qe, coeff);
	} catch (IOException localIOException) {
	    throw new InvalidKeyException("IOException: "
		    + localIOException.getMessage());
	}
    }

    public static PrivateKey decodePrivate(byte[] encoded)
	    throws InvalidKeyException {
	return decodePrivate(new ByteArrayInputStream(encoded));
    }

    public static PrivateKey generatePrivateKey(BigInteger v, BigInteger n,
	    BigInteger e, BigInteger d, BigInteger p, BigInteger q,
	    BigInteger pe, BigInteger qe, BigInteger coeff) throws InvalidKeyException {
	try {
	    return generatePrivate(new RSAPrivateKeySpec(n, d));
	} catch (InvalidKeySpecException ex) {
	    throw new InvalidKeyException(ex.getMessage(), ex);
	}
    }

    public static PrivateKey generatePrivateKey(BigInteger modulus,
	    BigInteger privateKeyExponent) throws InvalidKeyException {
	return generatePrivateKey(null, modulus, null, privateKeyExponent,
		null, null, null, null, null);
    }

    public static PublicKey generatePublic(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof X509EncodedKeySpec) {
	    try {
		byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
		PublicKey key = decodePublic(encoded);
		return translatePublic(key);
	    } catch (InvalidKeyException e) {
		throw new InvalidKeySpecException(
			"Could not create RSA public key", e);
	    }
	}
	if (keySpec instanceof RSAPublicKeySpec) {
	    try {
		return KeyFactory.getInstance("RSA").generatePublic(keySpec);
	    } catch (NoSuchAlgorithmException e) {
		throw new RuntimeException(
			"can not be happened, but RSA KeyFactory not support.",
			e);
	    }
	}
	throw new InvalidKeySpecException("Only RSAPublicKeySpec and "
		+ "X509EncodedKeySpec supported for RSA public keys");
    }

    public static PublicKey generatePublic(BigInteger modulus,
	    BigInteger exponent) throws InvalidKeyException {
	try {
	    return generatePublic(new RSAPublicKeySpec(modulus, exponent));
	} catch (InvalidKeySpecException e) {
	    throw new InvalidKeyException(e.getMessage(), e);
	}
    }

    public static PublicKey decodePublic(InputStream in)
	    throws InvalidKeyException {
	try {
	    DerValue publicKeyInfo = new DerValue(in);
	    if (publicKeyInfo.tag != 48) {
		throw new InvalidKeyException("invalid key format");
	    }
	    publicKeyInfo.data.getDerValue(); // read Algorithm ID
	    DerInputStream key = new DerInputStream(publicKeyInfo.data
		    .getUnalignedBitString().toByteArray());
	    DerValue derValue = key.getDerValue();
	    if (derValue.tag != DerValue.tag_Sequence) {
		throw new IOException("Not a SEQUENCE");
	    }
	    DerInputStream data = derValue.data;
	    BigInteger n = readPositiveBigInteger(data);
	    BigInteger e = readPositiveBigInteger(data);
	    if (publicKeyInfo.data.available() != 0)
		throw new InvalidKeyException("Extra key data");
	    return generatePublic(n, e);
	} catch (IOException localIOException) {
	    throw new InvalidKeyException("IOException: "
		    + localIOException.getMessage());
	}
    }

    public static PublicKey decodePublic(byte[] encodedKey)
	    throws InvalidKeyException {
	return decodePublic(new ByteArrayInputStream(encodedKey));
    }

    private static BigInteger readPositiveBigInteger(DerInputStream in)
	    throws IOException {
	return DataUtil.convertPositive(in.getBigInteger());
    }

}
