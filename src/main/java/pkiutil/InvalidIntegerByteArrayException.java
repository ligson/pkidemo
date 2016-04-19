package pkiutil;

/**
 * @author wang_xuanmin
 */
public class InvalidIntegerByteArrayException extends RuntimeException {

	private static final long serialVersionUID = -7954057689614939949L;

	public InvalidIntegerByteArrayException() {
	}

	public InvalidIntegerByteArrayException(String message) {
		super(message);
	}

	public InvalidIntegerByteArrayException(Throwable cause) {
		super(cause);
	}

	public InvalidIntegerByteArrayException(String message, Throwable cause) {
		super(message, cause);
	}

}
