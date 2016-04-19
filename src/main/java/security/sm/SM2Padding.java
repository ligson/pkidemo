package security.sm;

import java.security.SecureRandom;

public class SM2Padding {

	public static final int PAD_NONE = 0;
	private int type;

	public SM2Padding(int type, SecureRandom random) {
		this.type = type;
	}

	public static SM2Padding getInstance(int type, SecureRandom random) {
		return new SM2Padding(type, random);
	}

	public byte[] pad(byte[] data) {
		switch (type) {
		case PAD_NONE:
			return data;
		default:
			throw new AssertionError();
		}
	}

	public byte[] unpad(byte[] padded) {
		switch (type) {
		case PAD_NONE:
			return padded;
		default:
			throw new AssertionError();
		}
	}

}
