package security.sm;

import static pkiutil.DataUtil.trimZeroes;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.apache.commons.codec.binary.Hex;

import security.ec.ECUtil;
import security.util.DerInputStream;
import security.util.DerOutputStream;
import security.util.DerValue;
import security.util.ObjectIdentifier;
import security.x509.AlgorithmId;

/**
 * 
 * SM2 Signature
 * 
 * @author WangXuanmin ZhangHaisong
 */
public class SM2Signature extends SignatureSpi implements Cloneable {

	private static final ECParameterSpec sm2Curve = SM2Core.sm2Curve;
	private final MessageDigest md;
	private boolean digestReset;
	private ECPrivateKey privateKey; // s d
	private ECPublicKey publicKey; // w Q
	private SM2GenParameterSpec spec;

	protected SM2Signature(String digestAlgName, ObjectIdentifier digestOID,
			int encodedLength) {
		try {
			this.md = MessageDigest.getInstance(digestAlgName);
		} catch (NoSuchAlgorithmException e) {
			throw new ProviderException(e);
		}
		this.digestReset = true;
	}

	@Override
	protected void engineSetParameter(AlgorithmParameterSpec params)
			throws InvalidAlgorithmParameterException {
		if (this.digestReset == false) {
			throw new UnsupportedOperationException(
					"Can not set parameter after update()");
		}
		if (params instanceof SM2GenParameterSpec) {
			this.spec = (SM2GenParameterSpec) params;
			if (!this.spec.readyForGenerateZ()) {
				throw new InvalidAlgorithmParameterException(
						"Invalid SM2GenParameterSpce.");
			}
		} else {
			throw new InvalidAlgorithmParameterException(
					"Must be SM2GenParameterSpec.");
		}
	}

	private void initCommon(ECKey key, SecureRandom secureRandom)
			throws InvalidKeyException {
		resetDigest();
		if (this.appRandom == null) {
			this.appRandom = secureRandom;
		}
		this.spec = null;
	}

	private void resetDigest() {
		if (!(this.digestReset)) {
			this.md.reset();
			this.digestReset = true;
		}
	}

	private byte[] getDigestValue() {
		this.digestReset = true;
		return this.md.digest();
	}

	@Override
	protected void engineInitVerify(PublicKey publicKey)
			throws InvalidKeyException {
		ECPublicKey _t = (ECPublicKey) SM2KeyFactory.toSM2Key(publicKey);
		this.privateKey = null;
		this.publicKey = _t;
		initCommon(this.publicKey, null);
	}

	@Override
	protected void engineInitSign(PrivateKey privateKey)
			throws InvalidKeyException {
		SM2PrivateKey _t = (SM2PrivateKey) SM2KeyFactory.toSM2Key(privateKey);
		this.privateKey = _t;
		this.publicKey = null;
		initCommon(this.privateKey, null);
	}

	@Override
	protected void engineUpdate(byte b) throws SignatureException {
		this.updateZ();
		this.md.update(b);
		this.digestReset = false;
	}

	@Override
	protected void engineUpdate(byte[] b, int off, int len)
			throws SignatureException {
		this.updateZ();
		this.md.update(b, off, len);
		this.digestReset = false;
	}

	@Override
	protected byte[] engineSign() throws SignatureException {
		byte[] digest = getDigestValue();
		byte[] signedData = null;
		BigInteger r = null;
		BigInteger s = null;

		try {
			BigInteger k = null;
			do {
				do {
					BigInteger e = new BigInteger(1, digest);
					ECPoint kp = null;

					k = ECUtil.getRandomMultiple(sm2Curve);
					kp = ECUtil.getECPoint(sm2Curve, k);

					// r
					r = e.add(kp.getAffineX());
					r = r.mod(sm2Curve.getOrder());
				} while (r.equals(BigInteger.ZERO)
						|| r.add(k).equals(sm2Curve.getOrder()));

				// (1 + dA)~-1
				BigInteger dA_1 = privateKey.getS().add(BigInteger.ONE);
				dA_1 = dA_1.modInverse(sm2Curve.getOrder());
				s = r.multiply(privateKey.getS());
				s = k.subtract(s).mod(sm2Curve.getOrder());
				s = dA_1.multiply(s).mod(sm2Curve.getOrder());
			} while (s.equals(BigInteger.ZERO));

			DerOutputStream out = new DerOutputStream();
			out.write(DerValue.tag_Integer, trimZeroes(r.toByteArray()));
			out.write(DerValue.tag_Integer, trimZeroes(s.toByteArray()));
			signedData = trimZeroes(out.toByteArray());
		} catch (IOException e) {
			throw new SignatureException(e);
		}

		return signedData;
	}

	@Override
	protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
		boolean result = false;
		byte[] md = this.md.digest();
		BigInteger r = null;
		BigInteger s = null;
		try {
			DerInputStream dis = new DerInputStream(sigBytes);
			r = new BigInteger(1, dis.getBigInteger().toByteArray());
			s = new BigInteger(1, dis.getBigInteger().toByteArray());
		} catch (Exception e) {
			if (sigBytes.length == 64) {
				byte[] temp1 = new byte[32];
				byte[] temp2 = new byte[32];
				System.arraycopy(sigBytes, 0, temp1, 0, 32);
				System.arraycopy(sigBytes, 32, temp2, 0, 32);
				r = new BigInteger(1, temp1);
				s = new BigInteger(1, temp2);
			}
		}
		if (r == null || s == null) {
			throw new SignatureException("Parsing signature failed! "
					+ new String(Hex.encodeHex(sigBytes, false)));
		}

		BigInteger e = new BigInteger(1, md);
		BigInteger t = r.add(s).mod(sm2Curve.getOrder());

		if (t.equals(BigInteger.ZERO))
			return false;
		org.bouncycastle.math.ec.ECPoint point = ECUtil.getBC_ECGeneratorPoint(
				sm2Curve).multiply(s);
		point = point.add(ECUtil.convertToBC_ECPoint(sm2Curve.getCurve(),
				this.publicKey.getW()).multiply(t));
		BigInteger R = e.add(point.getX().toBigInteger()).mod(
				sm2Curve.getOrder());
		result = r.equals(R);
		return result;
	}

	@Override
	protected void engineSetParameter(String key, Object value)
			throws InvalidParameterException {
		if (this.digestReset == false) {
			throw new UnsupportedOperationException("Can not set " + P_USER_ID
					+ " or " + P_PUBLICKEY + " parameter after update()");
		}
		if (this.spec == null) {
			this.spec = new SM2GenParameterSpec();
		}
		if (P_PUBLICKEY.equalsIgnoreCase(key)) {
			if (value instanceof ECPublicKey) {
				try {
					this.spec.setPublicKey((ECPublicKey) value);
				} catch (InvalidKeyException e) {
					throw new InvalidParameterException(e.getMessage());
				}
			} else {
				throw new InvalidParameterException("Invalid value for "
						+ P_PUBLICKEY + ".");
			}
		} else if (P_USER_ID.equalsIgnoreCase(key)) {
			SM2UserID userID;
			if (value instanceof byte[]) {
				userID = new SM2UserID((byte[]) value);
			} else

			if (value instanceof SM2UserID) {
				userID = (SM2UserID) value;
			} else {
				throw new InvalidParameterException("Invalid value for "
						+ P_USER_ID + ".");
			}

			this.spec.setUserID(userID);
		} else {
			throw new InvalidParameterException("Unknown parameter key " + key
					+ ".");
		}
	}

	@Override
	protected Object engineGetParameter(String key)
			throws InvalidParameterException {
		if (P_USER_ID.equalsIgnoreCase(key)) {
			return this.spec.getUserID();
		}
		if (P_PUBLICKEY.equalsIgnoreCase(key)) {
			return this.spec.getPublicKey();
		}
		throw new InvalidParameterException("Unknown parameter key " + key
				+ ".");
	}

	private void updateZ() {
		// Nothing is updated when digestRest is true.
		if (this.digestReset == true && this.spec != null
				&& this.spec.readyForGenerateZ()) {
			byte[] Z = this.spec.generateZ();
			this.md.update(Z);
			this.spec = null;
			this.digestReset = false;
		}
	}

	public static final String P_USER_ID = "UserID";
	public static final String P_PUBLICKEY = "PublicKey";

	public static final class SM3withSM2 extends SM2Signature {
		public SM3withSM2() {
			super("SM3", AlgorithmId.SM3_oid, 32);
		}
	}

}
