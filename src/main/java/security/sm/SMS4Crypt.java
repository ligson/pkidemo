package security.sm;

import static java.lang.Integer.rotateLeft;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;

public class SMS4Crypt extends SymmetricCipher implements SMS4Constants {
	private static final byte[][] SBOX = {
			{ (byte) 0xd6, (byte) 0x90, (byte) 0xe9, (byte) 0xfe, (byte) 0xcc,
					(byte) 0xe1, (byte) 0x3d, (byte) 0xb7, (byte) 0x16,
					(byte) 0xb6, (byte) 0x14, (byte) 0xc2, (byte) 0x28,
					(byte) 0xfb, (byte) 0x2c, (byte) 0x05 },
			{ (byte) 0x2b, (byte) 0x67, (byte) 0x9a, (byte) 0x76, (byte) 0x2a,
					(byte) 0xbe, (byte) 0x04, (byte) 0xc3, (byte) 0xaa,
					(byte) 0x44, (byte) 0x13, (byte) 0x26, (byte) 0x49,
					(byte) 0x86, (byte) 0x06, (byte) 0x99 },
			{ (byte) 0x9c, (byte) 0x42, (byte) 0x50, (byte) 0xf4, (byte) 0x91,
					(byte) 0xef, (byte) 0x98, (byte) 0x7a, (byte) 0x33,
					(byte) 0x54, (byte) 0x0b, (byte) 0x43, (byte) 0xed,
					(byte) 0xcf, (byte) 0xac, (byte) 0x62 },
			{ (byte) 0xe4, (byte) 0xb3, (byte) 0x1c, (byte) 0xa9, (byte) 0xc9,
					(byte) 0x08, (byte) 0xe8, (byte) 0x95, (byte) 0x80,
					(byte) 0xdf, (byte) 0x94, (byte) 0xfa, (byte) 0x75,
					(byte) 0x8f, (byte) 0x3f, (byte) 0xa6 },
			{ (byte) 0x47, (byte) 0x07, (byte) 0xa7, (byte) 0xfc, (byte) 0xf3,
					(byte) 0x73, (byte) 0x17, (byte) 0xba, (byte) 0x83,
					(byte) 0x59, (byte) 0x3c, (byte) 0x19, (byte) 0xe6,
					(byte) 0x85, (byte) 0x4f, (byte) 0xa8 },
			{ (byte) 0x68, (byte) 0x6b, (byte) 0x81, (byte) 0xb2, (byte) 0x71,
					(byte) 0x64, (byte) 0xda, (byte) 0x8b, (byte) 0xf8,
					(byte) 0xeb, (byte) 0x0f, (byte) 0x4b, (byte) 0x70,
					(byte) 0x56, (byte) 0x9d, (byte) 0x35 },
			{ (byte) 0x1e, (byte) 0x24, (byte) 0x0e, (byte) 0x5e, (byte) 0x63,
					(byte) 0x58, (byte) 0xd1, (byte) 0xa2, (byte) 0x25,
					(byte) 0x22, (byte) 0x7c, (byte) 0x3b, (byte) 0x01,
					(byte) 0x21, (byte) 0x78, (byte) 0x87 },
			{ (byte) 0xd4, (byte) 0x00, (byte) 0x46, (byte) 0x57, (byte) 0x9f,
					(byte) 0xd3, (byte) 0x27, (byte) 0x52, (byte) 0x4c,
					(byte) 0x36, (byte) 0x02, (byte) 0xe7, (byte) 0xa0,
					(byte) 0xc4, (byte) 0xc8, (byte) 0x9e },
			{ (byte) 0xea, (byte) 0xbf, (byte) 0x8a, (byte) 0xd2, (byte) 0x40,
					(byte) 0xc7, (byte) 0x38, (byte) 0xb5, (byte) 0xa3,
					(byte) 0xf7, (byte) 0xf2, (byte) 0xce, (byte) 0xf9,
					(byte) 0x61, (byte) 0x15, (byte) 0xa1 },
			{ (byte) 0xe0, (byte) 0xae, (byte) 0x5d, (byte) 0xa4, (byte) 0x9b,
					(byte) 0x34, (byte) 0x1a, (byte) 0x55, (byte) 0xad,
					(byte) 0x93, (byte) 0x32, (byte) 0x30, (byte) 0xf5,
					(byte) 0x8c, (byte) 0xb1, (byte) 0xe3 },
			{ (byte) 0x1d, (byte) 0xf6, (byte) 0xe2, (byte) 0x2e, (byte) 0x82,
					(byte) 0x66, (byte) 0xca, (byte) 0x60, (byte) 0xc0,
					(byte) 0x29, (byte) 0x23, (byte) 0xab, (byte) 0x0d,
					(byte) 0x53, (byte) 0x4e, (byte) 0x6f },
			{ (byte) 0xd5, (byte) 0xdb, (byte) 0x37, (byte) 0x45, (byte) 0xde,
					(byte) 0xfd, (byte) 0x8e, (byte) 0x2f, (byte) 0x03,
					(byte) 0xff, (byte) 0x6a, (byte) 0x72, (byte) 0x6d,
					(byte) 0x6c, (byte) 0x5b, (byte) 0x51 },
			{ (byte) 0x8d, (byte) 0x1b, (byte) 0xaf, (byte) 0x92, (byte) 0xbb,
					(byte) 0xdd, (byte) 0xbc, (byte) 0x7f, (byte) 0x11,
					(byte) 0xd9, (byte) 0x5c, (byte) 0x41, (byte) 0x1f,
					(byte) 0x10, (byte) 0x5a, (byte) 0xd8 },
			{ (byte) 0x0a, (byte) 0xc1, (byte) 0x31, (byte) 0x88, (byte) 0xa5,
					(byte) 0xcd, (byte) 0x7b, (byte) 0xbd, (byte) 0x2d,
					(byte) 0x74, (byte) 0xd0, (byte) 0x12, (byte) 0xb8,
					(byte) 0xe5, (byte) 0xb4, (byte) 0xb0 },
			{ (byte) 0x89, (byte) 0x69, (byte) 0x97, (byte) 0x4a, (byte) 0x0c,
					(byte) 0x96, (byte) 0x77, (byte) 0x7e, (byte) 0x65,
					(byte) 0xb9, (byte) 0xf1, (byte) 0x09, (byte) 0xc5,
					(byte) 0x6e, (byte) 0xc6, (byte) 0x84 },
			{ (byte) 0x18, (byte) 0xf0, (byte) 0x7d, (byte) 0xec, (byte) 0x3a,
					(byte) 0xdc, (byte) 0x4d, (byte) 0x20, (byte) 0x79,
					(byte) 0xee, (byte) 0x5f, (byte) 0x3e, (byte) 0xd7,
					(byte) 0xcb, (byte) 0x39, (byte) 0x48 }, };

	// CK[i]=(ck[i,0],ck[i,1],ck[i,2],ck[i,3]) 32bit(8*4)
	// ck[i,j]=(4i+j)*7(mod 256)
	private static final int[] CK = { 0x00070e15, 0x1c232a31, 0x383f464d,
			0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
			0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65,
			0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
			0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d,
			0x848b9299, 0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
			0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279 };
	private static final int[] FK = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197,
			0xB27022DC };

	private static final int ROUND = 32;

	public boolean v = false;

	private int[] rk;

	private byte Sbox(byte src) {
		int row, column;
		row = src >> 4 & 0x0F;
		column = src & 0x0F;
		return SBOX[row][column];
	}

	private void F(int[] x, int[] rk, int i) throws IOException {
		x[(i + 0) % 4] ^= T(x[(i + 1) % 4] ^ x[(i + 2) % 4] ^ x[(i + 3) % 4]
				^ rk[i]);
	}

	private int T(int src) {
		return L(Tau(src));
	}

	private int T_(int src) {
		return L_(Tau(src));
	}

	private int Tau(int A) {
		byte[] a = convertToBytes(A);
		byte[] b = new byte[4];
		for (int i = 0; i < b.length; i++) {
			b[i] = Sbox(a[i]);
		}
		return convertToInt(b);
	}

	private int L(int B) {
		return B ^ rotateLeft(B, 2) ^ rotateLeft(B, 10) ^ rotateLeft(B, 18)
				^ rotateLeft(B, 24);
	}

	private int L_(int B) {
		return B ^ rotateLeft(B, 13) ^ rotateLeft(B, 23);
	}

	// reverse X
	private byte[] R(int[] x) {
		return convertToBytes(reverse(x));
	}

	private int[] R_(byte[] encBlock) throws IOException {
		return reverse(convertToIntArray(encBlock));
	}

	private int[] reverse(int[] in) {
		int[] out = in.clone();
		int leftOffset = 0;
		int rightOffset = out.length - 1;
		int temp;
		while (leftOffset < rightOffset) {
			temp = out[leftOffset];
			out[leftOffset] = out[rightOffset];
			out[rightOffset] = temp;
			leftOffset++;
			rightOffset--;
		}
		return out;
	}

	private byte[] convertToBytes(int[] in) {
		byte[] out = new byte[in.length << 2];
		for (int i = 0; i < in.length; i++) {
			System.arraycopy(convertToBytes(in[i]), 0, out, (0 + i << 2), 4);
		}
		return out;
	}

	private int[] convertToIntArray(byte[] in) throws IOException {
		assert in.length % 4 == 0;
		ByteArrayInputStream inputStream = new ByteArrayInputStream(in);
		int[] out = new int[in.length >> 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = readInt(inputStream);
		}
		return out;
	}

	// block 128bit
	// cipher block 32bit*4
	public byte[] encryptBlock(byte[] originBlock) throws IOException {
		int[] x = convertToIntArray(originBlock);
		for (int i = 0; i < ROUND; i++) {
			try {
				F(x, rk, i);
				if (v) {
					System.out.println("rk[" + i + "]="
							+ Integer.toHexString(rk[i]) + "    X[" + i + "]="
							+ Integer.toHexString(x[i % 4]));
				}
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
		byte[] encData = R(x);
		return encData;
	}

	public byte[] decryptBlock(byte[] encData) throws IOException {
		int[] x = R_(encData);
		for (int i = 0; i < ROUND; i++) {
			int index = ROUND - i - 1;
			try {
				F(x, rk, index);
				if (v) {
					System.out.println("rk[" + index + "]="
							+ Integer.toHexString(rk[index]) + "    X[" + index
							+ "]=" + Integer.toHexString(x[index % 4]));
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		byte[] decData = convertToBytes(x);
		return decData;
	}

	protected int[] genRk(byte[] mk) throws IOException {
		ByteArrayInputStream mkInStream = new ByteArrayInputStream(mk);
		int[] k = new int[4];
		int[] rk = new int[ROUND];
		for (int i = 0; i < 4; i++) {
			int mkElement;
			mkElement = readInt(mkInStream);
			k[i] = mkElement ^ FK[i];
		}
		for (int i = 0; i < ROUND; i++) {
			rk[i] = k[(i + 0) % 4] ^= T_(k[(i + 1) % 4] ^ k[(i + 2) % 4]
					^ k[(i + 3) % 4] ^ CK[i]);
		}
		return rk;
	}

	private int readInt(InputStream inputStream) throws IOException {
		byte[] n = new byte[4];
		if (inputStream.read(n) != 4) {
			throw new IOException("no integer in inputStream");
		}
		return convertToInt(n);
	}

	private int convertToInt(byte[] b) {
		int n = 0;
		for (int i = 0; i < 4; i++) {
			n = n | ((b[i] & 0xFF) << 8 * (3 - i));
		}
		return n;
	}

	private byte[] convertToBytes(int n) {
		byte[] b = new byte[4];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) (n >> 8 * (3 - i) & 0xFF);
		}
		return b;
	}

	// check if the specified length (in bytes) is a valid keysize for SMS4
	static final boolean isKeySizeValid(int len) {
		for (int i = 0; i < SMS4_KEYSIZES.length; i++) {
			if (len == SMS4_KEYSIZES[i]) {
				return true;
			}
		}
		return false;
	}

	@Override
	int getBlockSize() {
		return SMS4_BLOCK_SIZE;
	}

	@Override
	void init(boolean decrypting, String algorithm, byte[] key)
			throws InvalidKeyException {
		if (!algorithm.equalsIgnoreCase("SMS4")) {
			throw new InvalidKeyException(
					"Wrong algorithm: SMS4 required");
		}
		if (!isKeySizeValid(key.length)) {
			throw new InvalidKeyException("Invalid SMS4 key length: "
					+ key.length + " bytes");
		}

		// generate session round key.
		try {
			this.rk = genRk(key);
		} catch (IOException e) {
			throw new InvalidKeyException(e);
		}
	}

	@Override
	void encryptBlock(byte[] plain, int plainOffset, byte[] cipher,
			int cipherOffset) {
		byte[] oriData = new byte[SMS4_BLOCK_SIZE];
		byte[] encData = null;
		System.arraycopy(plain, plainOffset, oriData, 0, oriData.length);
		try {
			encData = encryptBlock(oriData);
			System.arraycopy(encData, 0, cipher, cipherOffset, encData.length);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	void decryptBlock(byte[] cipher, int cipherOffset, byte[] plain,
			int plainOffset) {
		byte[] encData = new byte[SMS4_BLOCK_SIZE];
		byte[] decData = null;
		System.arraycopy(cipher, cipherOffset, encData, 0, encData.length);
		try {
			decData = decryptBlock(encData);
			System.arraycopy(decData, 0, plain, plainOffset, decData.length);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
