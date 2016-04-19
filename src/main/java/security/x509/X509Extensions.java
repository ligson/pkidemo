package security.x509;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class X509Extensions implements java.security.cert.X509Extension {

	private ConcurrentHashMap<String, X509Extension> criticalExtns;
	private ConcurrentHashMap<String, X509Extension> nonCriticalExtns;
	private final static Set<String> EMPTY_SET = new HashSet<String>(0);

	public void add(String extnOID, byte[] extnValue, boolean critical) throws IOException {
		add(new X509Extension(new X509ExtensionIdentifier(extnOID), extnValue,
				critical));
	}

	public void add(X509ExtensionIdentifier extnID, byte[] extnValue,
			boolean critical) {
		add(new X509Extension(extnID, extnValue, critical));
	}

	public void add(X509Extension extn) {
		if (extn.isCritical()) {
			if (criticalExtns == null)
				criticalExtns = new ConcurrentHashMap<String, X509Extension>();
			criticalExtns.put(extn.getExtnID().toString(), extn);
		} else {
			if (nonCriticalExtns == null)
				nonCriticalExtns = new ConcurrentHashMap<String, X509Extension>();
			nonCriticalExtns.put(extn.getExtnID().toString(), extn);
		}
	}

	public Set<String> getCriticalExtensionOIDs() {
		if (criticalExtns != null)
			return criticalExtns.keySet();
		else
			return EMPTY_SET;
	}

	public byte[] getExtensionValue(String oid) {
		if (criticalExtns != null && criticalExtns.contains(oid))
			return criticalExtns.get(oid).getExtnValue();
		else if (nonCriticalExtns != null && nonCriticalExtns.contains(oid))
			return nonCriticalExtns.get(oid).getExtnValue();
		else
			return null;
	}

	public Set<String> getNonCriticalExtensionOIDs() {
		if (nonCriticalExtns != null)
			return nonCriticalExtns.keySet();
		else
			return EMPTY_SET;
	}

	public boolean hasUnsupportedCriticalExtension() {
		return hasUnsupportedCriticalExtension;
	}

	private boolean hasUnsupportedCriticalExtension = false;

	public void hasUnsupportedCriticalExtension(boolean unsupported) {
		this.hasUnsupportedCriticalExtension = unsupported;
	}

}
