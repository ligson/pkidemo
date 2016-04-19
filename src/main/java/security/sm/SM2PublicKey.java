package security.sm;

import java.io.IOException;
import java.io.ObjectStreamException;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;

import org.apache.commons.codec.binary.Hex;

import security.ec.ECParameters;
import security.x509.AlgorithmId;
import security.x509.X509Key;

public final class SM2PublicKey extends X509Key implements ECPublicKey {
	private ECPoint w; // Q
	private ECParameterSpec sm2Curve = SM2Core.sm2Curve;

	public SM2PublicKey(ECPoint point, ECParameterSpec params)
			throws InvalidKeyException, InvalidParameterSpecException {
		this.w = point;
		if (params != null && !params.equals(sm2Curve)) {
			throw new InvalidParameterSpecException(
					"need SM2 params, but "
							+ Hex.encodeHexString(ECParameters
									.encodeParameters(params)));
		}
		this.algid = new AlgorithmId(AlgorithmId.SM2_oid);

		this.key = ECParameters.encodePoint(point, params.getCurve());
	}

	public SM2PublicKey(byte[] encoded) throws InvalidKeyException {
		this.algid = new AlgorithmId(AlgorithmId.SM2_oid);
		if (encoded[0] == 0x04) {
			this.key = encoded;
			parseKeyBits();
		} else {
			decode(encoded);
		}
	}

	public String getAlgorithm() {
		return "SM2";
	}

	public ECPoint getW() {
		return this.w;
	}

	public ECParameterSpec getParams() {
		return this.sm2Curve;
	}

	public byte[] getEncoded() {
		return ((byte[]) this.key.clone());
	}

	protected void parseKeyBits() throws InvalidKeyException {
		try {
			this.w = ECParameters.decodePoint(this.key,
					this.sm2Curve.getCurve());
		} catch (IOException localIOException) {
			throw new InvalidKeyException("Invalid SM2 key", localIOException);
		}
	}

	public String toString() {
		return "Top SM2 public key, "
				+ this.sm2Curve.getCurve().getField().getFieldSize()
				+ " bits\n  public x coord: " + this.w.getAffineX()
				+ "\n  public y coord: " + this.w.getAffineY()
				+ "\n  parameters: " + this.sm2Curve;
	}

	protected Object writeReplace() throws ObjectStreamException {
		return new KeyRep(KeyRep.Type.PUBLIC, getAlgorithm(), getFormat(),
				getEncoded());
	}

}
