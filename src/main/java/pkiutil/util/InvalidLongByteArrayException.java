package pkiutil.util;

/**
 * @author wang_xuanmin
 */
public class InvalidLongByteArrayException extends RuntimeException {

	private static final long serialVersionUID = 5497627052780385646L;

	public InvalidLongByteArrayException() {
	}

	public InvalidLongByteArrayException(String message, Throwable cause) {
		super(message, cause);
	}

	public InvalidLongByteArrayException(String message) {
		super(message);
	}

	public InvalidLongByteArrayException(Throwable cause) {
		super(cause);
	}

}
