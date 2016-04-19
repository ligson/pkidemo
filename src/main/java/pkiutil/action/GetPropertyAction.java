package pkiutil.action;

import java.security.PrivilegedAction;

public class GetPropertyAction implements PrivilegedAction<String> {
	private String theProp;
	private String defaultVal;

	public GetPropertyAction(String paramString) {
		this.theProp = paramString;
	}

	public GetPropertyAction(String paramString1, String paramString2) {
		this.theProp = paramString1;
		this.defaultVal = paramString2;
	}

	public String run() {
		String str = System.getProperty(this.theProp);
		return ((str == null) ? this.defaultVal : str);
	}
}
