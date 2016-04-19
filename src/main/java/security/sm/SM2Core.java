package security.sm;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import security.ec.ECUtil;
import security.ec.NamedCurve;
import static pkiutil.DataUtil.*;

public final class SM2Core {
	protected final static ECParameterSpec sm2Curve = NamedCurve.getECParameterSpec("SM2");

	private ECPoint c1Point;
	private ECPoint encKeyBasePoint;
	private byte[] p2X;
	private byte[] p2Y;

	protected SM2Core(SM2PublicKey publicKey) {
		BigInteger k = ECUtil.getRandomMultiple(sm2Curve);
		this.c1Point = ECUtil.getECPoint(sm2Curve,k);
		this.encKeyBasePoint = ECUtil.multiply(sm2Curve.getCurve(),
				publicKey.getW(), k);
		p2X = trimZeroes(encKeyBasePoint.getAffineX().toByteArray());
		p2Y = trimZeroes(encKeyBasePoint.getAffineY().toByteArray());
	}

	protected SM2Core(ECPoint c1Point, SM2PrivateKey privateKey) {
		this.c1Point = c1Point;
		this.encKeyBasePoint = ECUtil.multiply(sm2Curve.getCurve(), c1Point,
				privateKey.getS());
		p2X = trimZeroes(encKeyBasePoint.getAffineX().toByteArray());
		p2Y = trimZeroes(encKeyBasePoint.getAffineY().toByteArray());
	}

	protected ECPoint c1Point() {
		return this.c1Point;
	}

	protected ECPoint getEncKeyBasePoint() {
		return this.encKeyBasePoint;
	}

	protected byte[] c3Hash(byte[] data) {
		MessageDigest sm3c3 = null;
		try {
			sm3c3 = MessageDigest.getInstance("SM3");
		} catch (NoSuchAlgorithmException e) {
			// can not be happened,but...
			e.printStackTrace();
		}
		sm3c3.update(p2X);
		sm3c3.update(data);
		sm3c3.update(p2Y);
		return sm3c3.digest();
	}

	protected byte[] c2Data(byte[] origin) {
		byte[] _data = origin.clone();
		int ct = 1;
		byte[] maskKey = _nextkey(ct++);
		for (int i = 0, keyOff = 0; i < _data.length; i++, keyOff++) {
			if (keyOff == maskKey.length) {
				maskKey = _nextkey(ct++);
				keyOff = 0;
			}
			_data[i] ^= maskKey[keyOff];
		}
		return _data;
	}

	private byte[] _nextkey(int ct) {
		MessageDigest maskKeyGen = null;
		try {
			maskKeyGen = MessageDigest.getInstance("SM3");
		} catch (NoSuchAlgorithmException e) {
			// can not be happened,but...
			e.printStackTrace();
		}
		byte[] key;
		maskKeyGen.update(p2X);
		maskKeyGen.update(p2Y);
		maskKeyGen.update((byte) (ct >> 24 & 0x00ff));
		maskKeyGen.update((byte) (ct >> 16 & 0x00ff));
		maskKeyGen.update((byte) (ct >> 8 & 0x00ff));
		maskKeyGen.update((byte) (ct & 0x00ff));
		key = maskKeyGen.digest();
		return key;
	}

}
