package security.x509;

public class X509Extension {
	/*-
	 * Extension  ::=  SEQUENCE  {
	 *      extnID      OBJECT IDENTIFIER,
	 *      critical    BOOLEAN DEFAULT FALSE,
	 *      extnValue   OCTET STRING  }
	 */
	private X509ExtensionIdentifier extnID;
	private boolean critical;
	private byte[] extnValue;

	public X509Extension(X509ExtensionIdentifier extnID, byte[] extnValue,
			boolean critical) {
		this.extnID = extnID;
		this.extnValue = extnValue;
		this.critical = critical;
	}

	public X509ExtensionIdentifier getExtnID() {
		return extnID;
	}

	public boolean isCritical() {
		return critical;
	}

	public byte[] getExtnValue() {
		return extnValue;
	}
}
