package security.sm;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;

import security.ec.ECUtil;
import security.jca.JCAUtil;

public class SM2KeyPairGenerator extends KeyPairGeneratorSpi {
	private static final ECParameterSpec sm2Curve = SM2Core.sm2Curve;
	private static final int KEYSIZE = sm2Curve.getCurve().getField()
			.getFieldSize();

	private SecureRandom random;

	@Override
	public void initialize(int keysize, SecureRandom random) {
		// key size is a constant. 256
		if (keysize != KEYSIZE) {
			throw new RuntimeException("SM2 key size must be 256.");
		}
		this.random = random;
	}

	public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
		if (!(params instanceof ECParameterSpec)) {
			throw new RuntimeException("Only ECParameterSpec supported");
		}
		this.random = random;
	}

	@Override
	public KeyPair generateKeyPair() {
		if (random == null) {
			random = JCAUtil.getSecureRandom();
		}
		BigInteger s; // BouncyCastal is named 'd'
		ECPoint w; // BouncyCastal is named 'Q'

		// generate s (EC d)
		s = ECUtil.getRandomMultiple(sm2Curve);
		// generate w (EC Q)
		w = ECUtil.getECPoint(sm2Curve,s);

		try {
			return new KeyPair(new SM2PublicKey(w, sm2Curve), new SM2PrivateKey(
					s, sm2Curve));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			e.printStackTrace();
		}
		// can not happened, but ...
		return null;
	}

}
