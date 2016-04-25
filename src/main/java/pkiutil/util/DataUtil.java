package pkiutil.util;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.ProviderException;

/**
 * @author wang_xuanmin
 */
public class DataUtil {
    /**
     * 长度为4的byte数组合成一个int.
     * 
     * @param b
     * @return
     */
    public static int bytes2int(byte[] b) {
	if (b.length > 4) {
	    throw new InvalidIntegerByteArrayException();
	}
	int mask = 0xff;
	int temp = 0;
	int res = 0;
	for (int i = 0; i < 4 - b.length; i++) {
	    res <<= 8;
	    res |= 0x00;
	}
	for (int i = 0; i < b.length; i++) {
	    res <<= 8;
	    temp = b[i] & mask;
	    res |= temp;
	}
	return res;
    }

    /**
     * int转换成长度为4的byte数组
     * 
     * @param num
     * @return
     */
    public static byte[] int2bytes(int num) {
	byte[] b = new byte[4];
	for (int i = 0; i < 4; i++) {
	    b[i] = (byte) (num >>> 24 - i * 8);
	}
	return b;
    }

    /**
     * 长度为8的byte数组合成一个long
     * 
     * @param b
     * @return
     */
    public static long bytes2long(byte[] b) {
	if (b.length > 8) {
	    throw new InvalidLongByteArrayException();
	}
	int mask = 0xff;
	int temp = 0;
	long res = 0;
	for (int i = 0; i < 8 - b.length; i++) {
	    res <<= 8;
	    res |= 0x00;
	}
	for (int i = 0; i < b.length; i++) {
	    res <<= 8;
	    temp = b[i] & mask;
	    res |= temp;
	}
	return res;
    }

    /**
     * long转换成长度为8的byte数组
     * 
     * @param num
     * @return
     */
    public static byte[] long2bytes(long num) {
	byte[] b = new byte[8];
	for (int i = 0; i < 8; i++) {
	    b[i] = (byte) (num >>> 56 - i * 8);
	}
	return b;
    }

    /**
     * 首字母大写
     * 
     * @param str
     * @return
     */
    public static String toFirstUpperCase(String str) {
	char[] ch = str.toCharArray();
	ch[0] = Character.toUpperCase(ch[0]);
	return new String(ch);
    }

    /**
     * <pre>
     * 转换Byte数组为十六进制表示字符串
     * use {@link org.apache.commons.codec.binary.Hex} instead
     * </pre>
     * 
     * @deprecated
     */
    public static String transformByteArrayToHexString(byte[] data,
	    boolean format) {
	if (data == null) {
	    return "(null)";
	}
	StringBuffer sb = new StringBuffer(data.length * 3);
	for (int i = 0; i < data.length; i++) {
	    int k = data[i] & 0xff;
	    if (i != 0 && format) {
		sb.append(' ');
	    }
	    sb.append(hexDigits[k >>> 4]);
	    sb.append(hexDigits[k & 0xf]);
	}
	return sb.toString();
    }

    /**
     * <pre>
     * 转换Byte数组为十六进制表示字符串
     * use {@link org.apache.commons.codec.binary.Hex} instead
     * </pre>
     * 
     * @deprecated
     */
    public static String transformByteArrayToHexString(byte[] data) {
	return transformByteArrayToHexString(data, false);
    }

    /**
     * <pre>
     * 转换Byte数组为十六进制表示字符串
     * use {@link org.apache.commons.codec.binary.Hex} instead
     * </pre>
     * 
     * @deprecated
     */
    public static byte[] transformHexStringToByteArray(String s) {
	s = s.replaceAll("[^0-9|^a-f|^A-F]", "");
	s = s.length() % 2 == 1 ? "0" + s.toUpperCase() : s.toUpperCase();

	char c = s.charAt(0);
	if (c == '8' || c == '9' || c == 'A' || c == 'B' || c == 'C'
		|| c == 'D' || c == 'E' || c == 'F') {
	    s = "00" + s;
	}
	byte[] b1 = s.getBytes();
	byte[] b2 = new byte[b1.length / 2];

	int j = 0;
	for (int i = 0; i < b1.length; i += 2, j++) {
	    int a = 0, b = 0;
	    if (b1[i] >= 48 && b1[i] <= 57) {
		a = b1[i] - 48;

	    } else if (b1[i] >= 65 && b1[i] <= 70) {
		a = b1[i] - 55;

	    }
	    if (b1[i + 1] >= 48 && b1[i + 1] <= 57) {
		b = b1[i + 1] - 48;
	    } else if (b1[i + 1] >= 65 && b1[i + 1] <= 70) {
		b = b1[i + 1] - 55;
	    }

	    b2[j] = (byte) ((a << 4) + b);
	}

	return b2;
    }

    public static byte[] convert(byte[] input, int offset, int len) {
	if ((offset == 0) && (len == input.length)) {
	    return input;
	} else {
	    byte[] t = new byte[len];
	    System.arraycopy(input, offset, t, 0, len);
	    return t;
	}
    }

    public static byte[] subarray(byte[] b, int ofs, int len) {
	byte[] out = new byte[len];
	System.arraycopy(b, ofs, out, 0, len);
	return out;
    }

    public static byte[] concat(byte[] b1, byte[] b2) {
	byte[] b = new byte[b1.length + b2.length];
	System.arraycopy(b1, 0, b, 0, b1.length);
	System.arraycopy(b2, 0, b, b1.length, b2.length);
	return b;
    }

    public static long[] concat(long[] b1, long[] b2) {
	if (b1.length == 0) {
	    return b2;
	}
	long[] b = new long[b1.length + b2.length];
	System.arraycopy(b1, 0, b, 0, b1.length);
	System.arraycopy(b2, 0, b, b1.length, b2.length);
	return b;
    }

    // trim leading (most significant) zeroes from the result
    public static byte[] trimZeroes(byte[] b) {
	int i = 0;
	while ((i < b.length - 1) && (b[i] == 0)) {
	    i++;
	}
	if (i == 0) {
	    return b;
	}
	byte[] t = new byte[b.length - i];
	System.arraycopy(b, i, t, 0, t.length);
	return t;
    }

    public static byte[] getMagnitude(BigInteger bi) {
	byte[] b = bi.toByteArray();
	if ((b.length > 1) && (b[0] == 0)) {
	    int n = b.length - 1;
	    byte[] newarray = new byte[n];
	    System.arraycopy(b, 1, newarray, 0, n);
	    b = newarray;
	}
	return b;
    }

    public static BigInteger convertPositive(BigInteger bi) {
	if (bi.signum() < 0) {
	    bi = new BigInteger(1, bi.toByteArray());
	}
	return bi;
    }

    public static byte[] getBytesUTF8(String s) {
	try {
	    return s.getBytes("UTF8");
	} catch (java.io.UnsupportedEncodingException e) {
	    throw new RuntimeException(e);
	}
    }

    public static byte[] sha1(byte[] data) {
	try {
	    MessageDigest md = MessageDigest.getInstance("SHA-1");
	    md.update(data);
	    return md.digest();
	} catch (GeneralSecurityException e) {
	    throw new ProviderException(e.getMessage());
	}
    }

    public static byte[] readFully(InputStream is, int length, boolean readAll)
	    throws IOException {
	byte[] output = {};
	if (length == -1)
	    length = Integer.MAX_VALUE;
	int pos = 0;
	while (pos < length) {
	    int bytesToRead;
	    if (pos >= output.length) { // Only expand when there's no room
		bytesToRead = Math.min(length - pos, output.length + 1024);
		if (output.length < pos + bytesToRead) {
		    output = copyOf(output, pos + bytesToRead);
		}
	    } else {
		bytesToRead = output.length - pos;
	    }
	    int cc = is.read(output, pos, bytesToRead);
	    if (cc < 0) {
		if (readAll && length != Integer.MAX_VALUE) {
		    throw new EOFException("Detect premature EOF");
		} else {
		    if (output.length != pos) {
			output = copyOf(output, pos);
		    }
		    break;
		}
	    }
	    pos += cc;
	}
	return output;
    }

    public static byte[] copyOf(byte[] original, int newLength) {
	byte[] copy = new byte[newLength];
	System.arraycopy(original, 0, copy, 0,
		Math.min(original.length, newLength));
	return copy;
    }

    private final static char[] hexDigits = "0123456789ABCDEF".toCharArray();

}
