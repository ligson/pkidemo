package security.sm;

import java.io.UnsupportedEncodingException;
import java.security.InvalidParameterException;

import common.TopSystem;

/**
 * SM2 algorithm parameter specification is a constant, but this is used for SM2
 * algorithm user's ID. Use getUserID() to get user's ID, thank you.
 * 
 * @author WangXuanmin
 * 
 */
public class SM2UserID {

	private byte[] userID;
	private int userIDLength = 16;
	private String charsetEncoding;

	public SM2UserID(byte[] userID) {
		checkUserID(userID);
		this.userID = userID;
	}

	public SM2UserID(byte[] userID, String charsetEncoding) {
		checkUserID(userID);
		this.userID = userID;
		this.charsetEncoding = charsetEncoding;
	}

	public byte[] getUserID() {
		return this.userID;
	}

	public String getCharsetEncoding() {
		if (this.charsetEncoding == null) {
			return TopSystem.FILE_ENCODING;
		}
		return this.charsetEncoding;
	}

	public String toString() {
		if (charsetEncoding != null) {
			try {
				return new String(userID, charsetEncoding);
			} catch (UnsupportedEncodingException e) {
			}
		}
		return new String(userID);
	}

	private void checkUserID(byte[] target) {
		if (target.length != this.userIDLength)
			throw new InvalidParameterException("UserID must be 16 bytes.");
	}

}
