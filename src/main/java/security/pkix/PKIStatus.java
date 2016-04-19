package security.pkix;

import java.math.BigInteger;

public class PKIStatus {
	public static final int GRANTED = 0;
	public static final int GRANTED_WITH_MODS = 1;
	public static final int REJECTION = 2;
	public static final int WAITING = 3;
	public static final int REVOCATION_WARNING = 4;
	public static final int REVOCATION_NOTIFICATION = 5;
	public static final int KEY_UPDATE_WARNING = 6;

	public static final PKIStatus granted = new PKIStatus(GRANTED);
	public static final PKIStatus grantedWithMods = new PKIStatus(
			GRANTED_WITH_MODS);
	public static final PKIStatus rejection = new PKIStatus(REJECTION);
	public static final PKIStatus waiting = new PKIStatus(WAITING);
	public static final PKIStatus revocationWarning = new PKIStatus(
			REVOCATION_WARNING);
	public static final PKIStatus revocationNotification = new PKIStatus(
			REVOCATION_NOTIFICATION);
	public static final PKIStatus keyUpdateWaiting = new PKIStatus(
			KEY_UPDATE_WARNING);

	private BigInteger value;

	public PKIStatus(int value) {
		this(BigInteger.valueOf(value));
	}

	public PKIStatus(BigInteger value) {
		this.value = value;
	}

	public BigInteger getValue() {
		return value;
	}
}
