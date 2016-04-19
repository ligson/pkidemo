package security.sm;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.apache.commons.codec.binary.Hex;

import security.ec.ECParameters;
import security.pkcs.PKCS8Key;
import security.util.DerInputStream;
import security.util.DerOutputStream;
import security.util.DerValue;
import security.x509.AlgorithmId;
import pkiutil.DataUtil;

public final class SM2PrivateKey extends PKCS8Key implements ECPrivateKey {
	private static final long serialVersionUID = 88695385615075129L;
	private BigInteger s; // d
	private ECParameterSpec sm2Curve = SM2Core.sm2Curve;

	public SM2PrivateKey(byte[] paramArrayOfByte) throws InvalidKeyException {
		decode(paramArrayOfByte);
	}

	public SM2PrivateKey(BigInteger s, ECParameterSpec params)
			throws InvalidKeyException, InvalidParameterSpecException {
		this.s = s;
		if (params!=null && !params.equals(sm2Curve)) {
			throw new InvalidParameterSpecException(
					"need SM2 params, but "
							+ Hex.encodeHexString(ECParameters
									.encodeParameters(params)));
		}
		this.algid = new AlgorithmId(AlgorithmId.SM2_oid);
		try {
			DerOutputStream localDerOutputStream = new DerOutputStream();
			localDerOutputStream.putInteger(1);
			byte[] arrayOfByte = DataUtil.trimZeroes(s.toByteArray());
			localDerOutputStream.putOctetString(arrayOfByte);
			DerValue localDerValue = new DerValue((byte) 48,
					localDerOutputStream.toByteArray());
			this.key = localDerValue.toByteArray();
		} catch (IOException e) {
			throw new InvalidKeyException(e);
		}
	}

	public String getAlgorithm() {
		return "SM2";
	}

	public BigInteger getS() {
		return this.s;
	}

	public ECParameterSpec getParams() {
		return this.sm2Curve;
	}

	public byte[] getEncodedPrivateValue() {
		return ((byte[]) this.key.clone());
	}

	protected void parseKeyBits() throws InvalidKeyException {
		try {
			DerInputStream localDerInputStream1 = new DerInputStream(this.key);
			DerValue localDerValue = localDerInputStream1.getDerValue();
			if (localDerValue.tag != 48) {
				throw new IOException("Not a SEQUENCE");
			}
			DerInputStream localDerInputStream2 = localDerValue.data;
			int i = localDerInputStream2.getInteger();
			if (i != 1) {
				throw new IOException("Version must be 1");
			}
			byte[] arrayOfByte = localDerInputStream2.getOctetString();
			this.s = new BigInteger(1, arrayOfByte);
			DerValue derValue;
			while (localDerInputStream2.available() != 0) {
				derValue = localDerInputStream2.getDerValue();
				if (!derValue.isContextSpecific((byte) 0)) {
					if (!derValue.isContextSpecific((byte) 1)) {
						throw new InvalidKeyException("Unexpected value: "
								+ derValue);
					}
				}
			}
		} catch (IOException localIOException) {
			throw new InvalidKeyException("Invalid EC private key",
					localIOException);
		}
	}

	public String toString() {
		return "Top SM2 private key, "
				+ this.sm2Curve.getCurve().getField().getFieldSize()
				+ " bits\n  private value:  " + this.s + "\n  parameters: "
				+ this.sm2Curve;
	}
}
