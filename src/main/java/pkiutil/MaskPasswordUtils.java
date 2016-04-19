package pkiutil;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Base64;

public class MaskPasswordUtils {
	private static final String KEY_ALGORITHM = "DES";
	private static final String CIPHER_ALGORITHM = "DES/CBC/PKCS5Padding";
	private static final byte[] keyBytes = getMachineCharacterCode();
	private static final byte[] iv = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 };

	public static byte[] encrypt(byte[] src) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		SecretKey deskey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, deskey, ivSpec);
		return cipher.doFinal(src);
	}

	public static byte[] decrypt(byte[] src) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		SecretKey deskey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, deskey, ivSpec);
		return cipher.doFinal(src);
	}

	public static byte[] getMachineCharacterCode() {
		byte[] tmpkeyBytes = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 };
		byte[] machineCharaterCodeBuf = null;
		try {
			machineCharaterCodeBuf = DataUtil.transformHexStringToByteArray(NetworkInfo.getMacAddress());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		int length = machineCharaterCodeBuf.length < tmpkeyBytes.length ? machineCharaterCodeBuf.length : tmpkeyBytes.length;
		System.arraycopy(machineCharaterCodeBuf, 0, tmpkeyBytes, 0, length);
		return tmpkeyBytes;
	}

	public static String encrypt(String Source) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] encoded = MaskPasswordUtils.encrypt(Source.getBytes());
		String strBase64 = new String(Base64.encode(encoded));
		return strBase64;
	}

	public static String decrypt(String Source) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] src = Base64.decode(Source);
		byte[] srcBytes = MaskPasswordUtils.decrypt(src);
		String str = new String(srcBytes);
		return str;
	}

	public static String getMachineCodePass() throws Exception {
		return MaskPasswordUtils.encrypt(NetworkInfo.getMacAddress());
	}
}