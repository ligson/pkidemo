package security.sm;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import security.jca.JCAUtil;

public class SMS4KeyGenerator extends KeyGeneratorSpi {

	private SecureRandom random = null;
	private int keySize = 16;

	@Override
	protected SecretKey engineGenerateKey() {
		SecretKeySpec sms4Key = null;

		if (this.random == null) {
			this.random = JCAUtil.getSecureRandom();
		}

		byte[] keyBytes = new byte[keySize];
		this.random.nextBytes(keyBytes);
		sms4Key = new SecretKeySpec(keyBytes, "SMS4");
		return sms4Key;
	}

	@Override
	protected void engineInit(SecureRandom random) {
		this.random = random;
	}

	@Override
	protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidAlgorithmParameterException {
		throw new InvalidAlgorithmParameterException(
				"SMS4 key generation does not take any parameters");
	}

	@Override
	protected void engineInit(int keysize, SecureRandom random) {
		if (((keysize % 8) != 0) || (!SMS4Crypt.isKeySizeValid(keysize / 8))) {
			throw new InvalidParameterException(
					"Wrong keysize: must be equal to "
							+ Arrays.toString(SMS4Constants.SMS4_KEYSIZES));
		}
		this.keySize = keysize / 8; // bytes keySize
		this.engineInit(random);
	}

}
