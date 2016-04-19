package security.ec;

import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import security.jca.JCAUtil;

/**
 * 
 * @author WangXuanmin
 * 
 */
public class ECUtil {
	/*-
	 * |----------------------------------------------------------------------------------------------
	 * | Standard          BouncyCastle
	 * | p                 p 
	 * | a                 a 
	 * | b                 b 
	 * | field(p)          q                 
	 * | curve(field,a,b)  curve(p,a,b)      the Curve along which the base point lies.
	 * | x                 x 
	 * | y                 y  
	 * | pointG(x,y)       pointG(g)         the Generator which is also known as the base point.
	 * | n                 n                 the Order of the generator.
	 * | h                 h 
	 * | S                 d 
	 * | pointPublic(W)    pointPublic(Q) 
	 * |-----------------------------------------------------------------------------------------------
	 */
	// ------------------ get EC parameters ------------------

	/* p(prime) */
	public static BigInteger getP(ECParameterSpec ecParameterSpce) {
		return getP(ecParameterSpce.getCurve());
	}

	/* p(prime) */
	public static BigInteger getP(EllipticCurve curve) {
		ECField field = curve.getField();
		if (field instanceof ECFieldFp)
			return ((ECFieldFp) field).getP();
		throw new IllegalArgumentException(field.getClass().getCanonicalName());
	}

	// ------------------ get BC object from ECParameterSpec ------------------

	/* ECCurve */
	public static org.bouncycastle.math.ec.ECCurve getBC_ECCurve(
			ECParameterSpec ecParameterSpcec) {
		return convertToBC_EllipticCurve(ecParameterSpcec.getCurve());
	}

	/* GeneratorPoint */
	public static org.bouncycastle.math.ec.ECPoint getBC_ECGeneratorPoint(
			ECParameterSpec ecParameterSpcec) {
		org.bouncycastle.math.ec.ECFieldElement ecc_gx_fieldelement = new org.bouncycastle.math.ec.ECFieldElement.Fp(
				getP(ecParameterSpcec), ecParameterSpcec.getGenerator()
						.getAffineX());
		org.bouncycastle.math.ec.ECFieldElement ecc_gy_fieldelement = new org.bouncycastle.math.ec.ECFieldElement.Fp(
				getP(ecParameterSpcec), ecParameterSpcec.getGenerator()
						.getAffineY());

		return new org.bouncycastle.math.ec.ECPoint.Fp(
				getBC_ECCurve(ecParameterSpcec), ecc_gx_fieldelement,
				ecc_gy_fieldelement);
	}

	// ------------------ convert to BC object ------------------

	/* ECParameterSpec */
	public static org.bouncycastle.jce.spec.ECParameterSpec convertBC_ECParameterSpec(
			ECParameterSpec ecParameterSpec) {
		return new org.bouncycastle.jce.spec.ECParameterSpec(
				getBC_ECCurve(ecParameterSpec),
				getBC_ECGeneratorPoint(ecParameterSpec),
				ecParameterSpec.getOrder());
	}

	/* ECCurve */
	public static org.bouncycastle.math.ec.ECCurve convertToBC_EllipticCurve(
			EllipticCurve curve) {
		return new org.bouncycastle.math.ec.ECCurve.Fp(getP(curve),
				curve.getA(), curve.getB());
	}

	/* ECPoint */
	public static org.bouncycastle.math.ec.ECPoint convertToBC_ECPoint(
			EllipticCurve curve, ECPoint point) {

		if (curve.getField() instanceof ECFieldFp) {
			org.bouncycastle.math.ec.ECFieldElement x = new org.bouncycastle.math.ec.ECFieldElement.Fp(
					getP(curve), point.getAffineX());
			org.bouncycastle.math.ec.ECFieldElement y = new org.bouncycastle.math.ec.ECFieldElement.Fp(
					getP(curve), point.getAffineY());
			return new org.bouncycastle.math.ec.ECPoint.Fp(
					convertToBC_EllipticCurve(curve), x, y);
		}
		throw new IllegalArgumentException(curve.getClass().getCanonicalName());
	}

	// ------------------ revert from BC object ------------------

	/* ECParameterSpec */
	public static ECParameterSpec revertFromBC_ECParameterSpec(
			org.bouncycastle.jce.spec.ECParameterSpec bcECParameterSpec) {
		return new ECParameterSpec(
				revertFromBC_EllipticCurve(bcECParameterSpec.getCurve()),
				revertFromBC_ECPoint(bcECParameterSpec.getG()),
				bcECParameterSpec.getN(), bcECParameterSpec.getH().intValue());
	}

	/* ECCurve */
	public static EllipticCurve revertFromBC_EllipticCurve(
			org.bouncycastle.math.ec.ECCurve bcCurve) {
		if (bcCurve instanceof org.bouncycastle.math.ec.ECCurve.Fp) {
			org.bouncycastle.math.ec.ECCurve.Fp p = (org.bouncycastle.math.ec.ECCurve.Fp) bcCurve;
			return new EllipticCurve(new ECFieldFp(p.getQ()), p.getA()
					.toBigInteger(), p.getB().toBigInteger());
		}
		throw new IllegalArgumentException(bcCurve.getClass()
				.getCanonicalName());
	}

	/* ECPoint */
	public static ECPoint revertFromBC_ECPoint(
			org.bouncycastle.math.ec.ECPoint bcECPoint) {
		return new ECPoint(bcECPoint.getX().toBigInteger(), bcECPoint.getY()
				.toBigInteger());
	}

	// -------------------- multiply ----------------
	public static ECPoint multiply(EllipticCurve curve, ECPoint point,
			BigInteger k) {
		return revertFromBC_ECPoint(convertToBC_ECPoint(curve, point).multiply(
				k));
	}

	/**
	 * get a random number between zero and the order(n) of the curve
	 */
	public static final BigInteger getRandomMultiple(ECParameterSpec curve) {
		BigInteger d;
		BigInteger n = curve.getOrder();
		int nBitLength = n.bitLength();
		do {
			d = new BigInteger(nBitLength, JCAUtil.getSecureRandom());
		} while (d.equals(BigInteger.ZERO) || (d.compareTo(n) >= 0));
		return d;
	}

	/**
	 * get a point in the curve
	 */
	public static final ECPoint getECPoint(ECParameterSpec curve,
			BigInteger multiple) {
		BigInteger n = curve.getOrder();
		if (multiple.equals(BigInteger.ZERO) || (multiple.compareTo(n) >= 0)) {
			throw new InvalidParameterException("Multiple:"
					+ multiple.toString());
		}
		return ECUtil.revertFromBC_ECPoint(ECUtil.getBC_ECGeneratorPoint(curve)
				.multiply(multiple));
	}
}
