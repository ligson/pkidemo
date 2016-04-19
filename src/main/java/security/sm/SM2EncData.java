package security.sm;

import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.ECPoint;

import org.apache.commons.codec.binary.Hex;

import security.util.DerInputStream;
import security.util.DerOutputStream;
import security.util.DerValue;
import static pkiutil.DataUtil.*;

public class SM2EncData {
	private ECPoint c1Point;
	private byte[] c3Hash;
	private byte[] c2Data;

	public SM2EncData() {
	}

	public SM2EncData(byte[] sm2EncData) throws IOException {
		DerInputStream sequence = new DerInputStream(sm2EncData);
		DerValue[] vector = sequence.getSequence(4);
		if (vector.length != 4) {
			throw new IOException("Invalid data");
		}
		BigInteger x = vector[0].getPositiveBigInteger();
		BigInteger y = vector[1].getPositiveBigInteger();
		c1Point = new ECPoint(x, y);
		byte[] data1 = vector[2].getOctetString();
		byte[] data2 = vector[3].getOctetString();
		if (data1.length == 32) {
			c3Hash = data1;
			c2Data = data2;
		} else {
			c2Data = data2;
			c3Hash = data1;
		}
	}

	public byte[] getEncoded() {
		DerOutputStream sequence = new DerOutputStream();
		DerOutputStream vector = new DerOutputStream();
		try {
			vector.write(DerValue.tag_Integer, trimZeroes(c1Point.getAffineX()
					.toByteArray()));
			vector.write(DerValue.tag_Integer, trimZeroes(c1Point.getAffineY()
					.toByteArray()));
			vector.write(DerValue.tag_OctetString, c3Hash);
			vector.write(DerValue.tag_OctetString, c2Data);
			sequence.write(DerValue.tag_Sequence, vector);
		} catch (IOException e) {
			// can not be happened,but...
			e.printStackTrace();
		}
		return sequence.toByteArray();
	}

	public void setC1Point(ECPoint c1Point) {
		this.c1Point = c1Point;
	}

	public void setC3Hash(byte[] c3Hash) {
		this.c3Hash = c3Hash;
	}

	public void setC2Data(byte[] c2Data) {
		this.c2Data = c2Data;
	}

	public ECPoint getC1Point() {
		return this.c1Point;
	}

	public byte[] getC3Hash() {
		return c3Hash;
	}

	public byte[] getC2Data() {
		return c2Data;
	}

	@Override
	public String toString() {
		StringBuilder info = new StringBuilder(32 + 32 + 32 + 1024);
		info.append("SM2 encrypted data [");
		info.append("X:" + c1Point.getAffineX().toString(16));
		info.append(", Y:" + c1Point.getAffineY().toString(16));
		info.append(", Hash(" + c3Hash.length + "):"
				+ Hex.encodeHexString(c3Hash));
		info.append(", EncData(" + c2Data.length + "):"
				+ Hex.encodeHexString(c2Data));
		info.append("]\n");
		info.append("DER:\n");
		info.append(Hex.encodeHexString(getEncoded()) + "\n");
		return info.toString();
	}

}
