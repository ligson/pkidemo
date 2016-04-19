package security.sm;

import java.security.MessageDigestSpi;

/**
 *
 * SM3 Algorithm
 * @author ZhangHaisong
 * 
 * SM3 MessageDigest
 * @author WangXuanmin
 */
public class SM3MessageDigest extends MessageDigestSpi implements Cloneable {

	/**
	 * Standard constructor
	 */
	public SM3MessageDigest() {
		xBuf = new byte[4];
		xBufOff = 0;
		reset();
	}

	@Override
	protected void engineUpdate(byte input) {
		update(input);
	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		update(input, offset, len);
	}

	@Override
	protected byte[] engineDigest() {
		byte[] digest = new byte[32];
		if (doFinal(digest, 0) > 0) {
			return digest;
		}
		return null;
	}

	@Override
	protected void engineReset() {
		reset();
	}

	private static final int DIGEST_LENGTH = 32;

	private static final int v0[] = { 0x7380166f, 0x4914b2b9, 0x172442d7,
			0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e };

	private int[] v = new int[8];
	private int[] v_ = new int[8];

	private static final int[] X0 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0 };

	private int[] X = new int[68];
	private int xOff;

	private int T_00_15 = 0x79cc4519;
	private int T_16_63 = 0x7a879d8a;

	protected void reset() {
		byteCount = 0;

		xBufOff = 0;
		for (int i = 0; i < xBuf.length; i++) {
			xBuf[i] = 0;
		}

		System.arraycopy(v0, 0, v, 0, v0.length);

		xOff = 0;
		System.arraycopy(X0, 0, X, 0, X0.length);
	}

	protected void processBlock() {
		int i;

		int ww[] = X;
		int ww_[] = new int[64];

		for (i = 16; i < 68; i++) {
			ww[i] = P1(ww[i - 16] ^ ww[i - 9] ^ (ROTATE(ww[i - 3], 15)))
					^ (ROTATE(ww[i - 13], 7)) ^ ww[i - 6];
		}

		for (i = 0; i < 64; i++) {
			ww_[i] = ww[i] ^ ww[i + 4];
		}

		int vv[] = v;
		int vv_[] = v_;

		System.arraycopy(vv, 0, vv_, 0, v0.length);

		int SS1, SS2, TT1, TT2, aaa;
		for (i = 0; i < 16; i++) {
			aaa = ROTATE(vv_[0], 12);
			SS1 = aaa + vv_[4] + ROTATE(T_00_15, i);
			SS1 = ROTATE(SS1, 7);
			SS2 = SS1 ^ aaa;

			TT1 = FF_00_15(vv_[0], vv_[1], vv_[2]) + vv_[3] + SS2 + ww_[i];
			TT2 = GG_00_15(vv_[4], vv_[5], vv_[6]) + vv_[7] + SS1 + ww[i];
			vv_[3] = vv_[2];
			vv_[2] = ROTATE(vv_[1], 9);
			vv_[1] = vv_[0];
			vv_[0] = TT1;
			vv_[7] = vv_[6];
			vv_[6] = ROTATE(vv_[5], 19);
			vv_[5] = vv_[4];
			vv_[4] = P0(TT2);
		}
		for (i = 16; i < 64; i++) {
			aaa = ROTATE(vv_[0], 12);
			SS1 = aaa + vv_[4] + ROTATE(T_16_63, i);
			SS1 = ROTATE(SS1, 7);
			SS2 = SS1 ^ aaa;

			TT1 = FF_16_63(vv_[0], vv_[1], vv_[2]) + vv_[3] + SS2 + ww_[i];
			TT2 = GG_16_63(vv_[4], vv_[5], vv_[6]) + vv_[7] + SS1 + ww[i];
			vv_[3] = vv_[2];
			vv_[2] = ROTATE(vv_[1], 9);
			vv_[1] = vv_[0];
			vv_[0] = TT1;
			vv_[7] = vv_[6];
			vv_[6] = ROTATE(vv_[5], 19);
			vv_[5] = vv_[4];
			vv_[4] = P0(TT2);
		}
		for (i = 0; i < 8; i++) {
			vv[i] ^= vv_[i];
		}

		// Reset
		xOff = 0;
		System.arraycopy(X0, 0, X, 0, X0.length);
	}

	protected void processWord(byte[] in, int inOff) {
		int n = in[inOff] << 24;
		n |= (in[++inOff] & 0xff) << 16;
		n |= (in[++inOff] & 0xff) << 8;
		n |= (in[++inOff] & 0xff);
		X[xOff] = n;

		if (++xOff == 16) {
			processBlock();
		}
	}

	protected void processLength(long bitLength) {
		if (xOff > 14) {
			processBlock();
		}

		X[14] = (int) (bitLength >>> 32);
		X[15] = (int) (bitLength & 0xffffffff);
	}

	protected static void intToBigEndian(int n, byte[] bs, int off) {
		bs[off] = (byte) (n >>> 24);
		bs[++off] = (byte) (n >>> 16);
		bs[++off] = (byte) (n >>> 8);
		bs[++off] = (byte) (n);
	}

	protected int doFinal(byte[] out, int outOff) {
		finish();

		for (int i = 0; i < 8; i++) {
			intToBigEndian(v[i], out, outOff + i * 4);
		}

		reset();

		return DIGEST_LENGTH;
	}

	protected String getAlgorithmName() {
		return "SM3";
	}

	protected int getDigestSize() {
		return DIGEST_LENGTH;
	}

	private int ROTATE(int x, int n) {
		return (x << n) | (x >>> (32 - n));
	}

	private int P0(int X) {
		return ((X) ^ ROTATE((X), 9) ^ ROTATE((X), 17));
	}

	private int P1(int X) {
		return ((X) ^ ROTATE((X), 15) ^ ROTATE((X), 23));
	}

	private int FF_00_15(int X, int Y, int Z) {
		return (X ^ Y ^ Z);
	}

	private int FF_16_63(int X, int Y, int Z) {
		return ((X & Y) | (X & Z) | (Y & Z));
	}

	private int GG_00_15(int X, int Y, int Z) {
		return (X ^ Y ^ Z);
	}

	private int GG_16_63(int X, int Y, int Z) {
		return ((X & Y) | (~X & Z));
	}

	private static final int BYTE_LENGTH = 64;
	private byte[] xBuf;
	private int xBufOff;

	private long byteCount;

	protected void update(byte in) {
		xBuf[xBufOff++] = in;

		if (xBufOff == xBuf.length) {
			processWord(xBuf, 0);
			xBufOff = 0;
		}

		byteCount++;
	}

	protected void update(byte[] in, int inOff, int len) {
		//
		// fill the current word
		//
		while ((xBufOff != 0) && (len > 0)) {
			update(in[inOff]);

			inOff++;
			len--;
		}

		//
		// process whole words.
		//
		while (len > xBuf.length) {
			processWord(in, inOff);

			inOff += xBuf.length;
			len -= xBuf.length;
			byteCount += xBuf.length;
		}

		//
		// load in the remainder.
		//
		while (len > 0) {
			update(in[inOff]);

			inOff++;
			len--;
		}
	}

	protected void finish() {
		long bitLength = (byteCount << 3);

		//
		// add the pad bytes.
		//
		update((byte) 128);

		while (xBufOff != 0) {
			update((byte) 0);
		}

		processLength(bitLength);

		processBlock();
	}

	protected int engineGetDigestLength() {
		return BYTE_LENGTH;
	}

}
