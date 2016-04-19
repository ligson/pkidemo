package security.pkix;

public class PKIStatusInfo {
	/*-
	 * PKIStatusInfo ::= SEQUENCE {
	 *	    status        PKIStatus,
	 *	    statusString  PKIFreeText     OPTIONAL,
	 *	    failInfo      PKIFailureInfo  OPTIONAL  }
	 */
	private PKIStatus status;
	private PKIFreeText statusString;
	private PKIFailureInfo failInfo;

	public PKIStatusInfo(PKIStatus status, PKIFreeText statusString,
			PKIFailureInfo failInfo) {
		this.status = status;
		this.statusString = statusString;
		this.failInfo = failInfo;
	}

	public PKIStatus getStatus() {
		return status;
	}

	public PKIFreeText getStatusString() {
		return statusString;
	}

	public PKIFailureInfo getFailInfo() {
		return failInfo;
	}

}
