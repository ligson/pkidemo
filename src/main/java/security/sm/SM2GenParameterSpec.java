package security.sm;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

import security.ec.NamedCurve;


public class SM2GenParameterSpec extends ECGenParameterSpec {

	private SM2UserID userID;
	private ECPublicKey publicKey;

	protected SM2GenParameterSpec() {
		super("SM2GenParameterSpec");
	}

	public SM2GenParameterSpec(String userIDString) {
		super(userIDString);
		this.userID = new SM2UserID(userIDString.getBytes());
	}

	/**
	 * @param userID
	 * @param publicKey
	 * @throws InvalidKeyException
	 */
	public SM2GenParameterSpec(SM2UserID userID, PublicKey publicKey)
			throws InvalidKeyException {
		super(userID.toString());
		this.userID = userID;
		this.publicKey = (ECPublicKey) SM2KeyFactory.toSM2Key(publicKey);
	}

	public SM2UserID getUserID() {
		return userID;
	}

	public void setUserID(SM2UserID userID) {
		this.userID = userID;
	}

	public ECPublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) throws InvalidKeyException {
		this.publicKey = (ECPublicKey) SM2KeyFactory.toSM2Key(publicKey);
	}

	public boolean readyForGenerateZ() {
		return this.userID != null && this.publicKey != null;
	}

	public byte[] generateZ() {
		if (this.userID == null)
			throw new NullPointerException("userID can not be null.");
		if (this.publicKey == null)
			throw new NullPointerException("publicKey can not be null.");

		ECParameterSpec sm2curve = NamedCurve.getECParameterSpec("SM2");

		String digestAlgName = "SM3";
		MessageDigest zMD;
		try {
			zMD = MessageDigest.getInstance(digestAlgName);
			zMD.reset();

			// userId length
			int len = userID.getUserID().length * 8;
			zMD.update((byte) (len >> 8 & 0x00ff));
			zMD.update((byte) (len & 0x00ff));

			// userId
			zMD.update(userID.getUserID());

			// a,b
			zMD.update(sm2curve.getCurve().getA().toByteArray());
			zMD.update(sm2curve.getCurve().getB().toByteArray());

			// gx,gy
			zMD.update(sm2curve.getGenerator().getAffineX().toByteArray());
			zMD.update(sm2curve.getGenerator().getAffineY().toByteArray());

			// x,y
			zMD.update(this.publicKey.getW().getAffineX().toByteArray());
			zMD.update(this.publicKey.getW().getAffineY().toByteArray());

			// Z
			return zMD.digest();
		} catch (NoSuchAlgorithmException e) {
			// can not be happened, but...
			e.printStackTrace();
		}
		return null;
	}
}
