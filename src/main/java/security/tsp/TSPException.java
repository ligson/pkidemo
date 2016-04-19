package security.tsp;

public class TSPException extends Exception {

	private static final long serialVersionUID = 4522589227266330184L;

	Exception underlyingException;

	public TSPException(String message) {
		super(message);
	}

	public TSPException(String message, Exception e) {
		super(message);
		underlyingException = e;
	}

	public Exception getUnderlyingException() {
		return underlyingException;
	}

	public Throwable getCause() {
		return underlyingException;
	}

}
