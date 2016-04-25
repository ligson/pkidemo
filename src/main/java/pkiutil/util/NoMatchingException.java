package pkiutil.util;

public class NoMatchingException extends Exception {

	private static final long serialVersionUID = 1601549184730617118L;

	public NoMatchingException() {
		super();
	}

	public NoMatchingException(String message, Throwable cause) {
		super(message, cause);
	}

	public NoMatchingException(String message) {
		super(message);
	}

	public NoMatchingException(Throwable cause) {
		super(cause);
	}

}
