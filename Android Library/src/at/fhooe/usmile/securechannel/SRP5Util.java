package at.fhooe.usmile.securechannel;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.Fp;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP192R1Field;
import org.bouncycastle.math.ec.custom.sec.SecP192R1FieldElement;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.BigIntegers;

public class SRP5Util {
	private static BigInteger ZERO = BigInteger.valueOf(0);
	private static BigInteger ONE = BigInteger.valueOf(1);

	public static BigInteger calculateK(Digest digest, BigInteger n,
			BigInteger g) {
		return hashPaddedPair(digest, n, n, g);
	}

	public static BigInteger calculateU(Digest digest, BigInteger n,
			BigInteger A, BigInteger B) {
		return hashPaddedPair(digest, n, A, B);
	}

	public static BigInteger calculateUPi(Digest digest, BigInteger n,
			byte[] salt, byte[] identity, byte[] password) {
		byte[] output = new byte[digest.getDigestSize()];

		digest.update(identity, 0, identity.length);
		digest.update((byte) ':');
		digest.update(password, 0, password.length);
		digest.doFinal(output, 0);

		digest.update(salt, 0, salt.length);
		digest.update(output, 0, output.length);
		digest.doFinal(output, 0);

		return new BigInteger(1, output).mod(n);
	}


	public static BigInteger generatePrivateValue(Digest digest, BigInteger N,
			BigInteger g, SecureRandom random) {
		int minBits = Math.min(256, N.bitLength() / 2);
		BigInteger min = ONE.shiftLeft(minBits - 1);
		BigInteger max = N.subtract(ONE);

		return BigIntegers.createRandomInRange(min, max, random);
	}

	public static BigInteger validatePublicValue(BigInteger N, BigInteger val)
			throws CryptoException {
		val = val.mod(N);

		// Check that val % N != 0
		if (val.equals(ZERO)) {
			throw new CryptoException("Invalid public value: 0");
		}

		return val;
	}

	private static BigInteger hashPaddedPair(Digest digest, BigInteger N,
			BigInteger n1, BigInteger n2) {
		int padLength = (N.bitLength() + 7) / 8;

		byte[] n1_bytes = getPadded(n1, padLength);
		byte[] n2_bytes = getPadded(n2, padLength);

		digest.update(n1_bytes, 0, n1_bytes.length);
		digest.update(n2_bytes, 0, n2_bytes.length);

		byte[] output = new byte[digest.getDigestSize()];
		digest.doFinal(output, 0);

		return new BigInteger(1, output).mod(N);
	}

	private static byte[] getPadded(BigInteger n, int length) {
		byte[] bs = n.toByteArray();
		if (bs.length < length) {
			byte[] tmp = new byte[length];
			System.arraycopy(bs, 0, tmp, length - bs.length, bs.length);
			bs = tmp;
		} else if (bs.length > length) { //BigInteger bigger (probably due to 0 padding)
			byte[] tmp = new byte[length];
			System.arraycopy(bs, bs.length-length, tmp, 0, length);
			bs = tmp;
		}
		return bs;
	}

	public static ECPoint Redp1(ECParameterSpec ecSpec,Digest digest,byte[] oPi) {
		byte[] o1 = new byte[digest.getDigestSize()];
		digest.update(oPi,0,oPi.length);
		digest.doFinal(o1, 0);
		
		BigInteger i1 = OS2IP(o1);
		ECPoint outputE = computeRandomPoint(ecSpec, digest, i1,0);

		return outputE;
	}

	private static ECPoint computeRandomPoint(ECParameterSpec ecSpec, Digest digest,
			BigInteger i1, int counter) {
		byte[] o2 = getPadded(i1, digest.getDigestSize());
		byte[] o3 = new byte[digest.getDigestSize()];
		digest.update(o2, 0, o2.length);
		digest.doFinal(o3, 0);

		BigInteger q = ecSpec.getCurve().getField().getCharacteristic();
		
		ECFieldElement x = I2FEP(ecSpec, OS2IP(o3).mod(q));
		ECFieldElement y = null;
		
		ECPoint outputE = null;
		
		if (BigInteger.ZERO.compareTo(x.toBigInteger()) != 0){
			byte mu = (byte) (i1.toByteArray()[0] & 0x01);
			if(ECAlgorithms.isF2mCurve(ecSpec.getCurve())){ 
				//TODO				
			} else if(ECAlgorithms.isFpCurve(ecSpec.getCurve())) { 
				BigInteger p = ecSpec.getCurve().getField().getCharacteristic();

				if (BigInteger.valueOf(3).compareTo(p) == 0){
					
				} else if (BigInteger.valueOf(3).compareTo(p) == -1){
					//p is greater than 3
		            ECFieldElement rhs = x.square().add(ecSpec.getCurve().getA()).multiply(x).add(ecSpec.getCurve().getB());
		            ECFieldElement beta = I2FEP(ecSpec, findSquareRoot(rhs.toBigInteger(), q));
					
					if((beta==null || beta.square().toBigInteger().compareTo(rhs.toBigInteger())!=0) && counter<=5) { //No point found, increase i and go back to o2 generation
//						System.out.println("No Point found, increase i by one " + counter);
						return computeRandomPoint(ecSpec, digest, i1.add(ONE),++counter);
					} else {
						if(mu == 1){
							y = beta.negate();
							System.out.println("NEGATED BETA");
						} else if(mu == 0){
							//Do nothing
							y = beta;
						}
						outputE = ecSpec.getCurve().createPoint(x.toBigInteger(), y.toBigInteger());
						outputE = ecSpec.getCurve().validatePoint(x.toBigInteger(), y.toBigInteger());
						if(outputE!=null){
							System.out.println("counter : "+ counter);
//							System.out.println("REDP point: "+ outputE.toString());
//							System.out.println("is point on curve " + outputE.isValid());
							outputE=outputE.multiply(ecSpec.getCurve().getCofactor());
						}
					}
				}
					
			}
		}
		return outputE;
	}
	
	private static ECFieldElement sqrt192r1(BigInteger x, ECParameterSpec ecspec)
	    {
	        // Raise this element to the exponent 2^190 - 2^62

	        int[] x1 = Nat192.fromBigInteger(x);
	        if (Nat192.isZero(x1) || Nat192.isOne(x1))
	        {
	            return null;
	        }

	        int[] t1 = Nat192.create();
	        int[] t2 = Nat192.create();

	        SecP192R1Field.square(x1, t1);
	        SecP192R1Field.multiply(t1, x1, t1);

	        SecP192R1Field.squareN(t1, 2, t2);
	        SecP192R1Field.multiply(t2, t1, t2);

	        SecP192R1Field.squareN(t2, 4, t1);
	        SecP192R1Field.multiply(t1, t2, t1);

	        SecP192R1Field.squareN(t1, 8, t2);
	        SecP192R1Field.multiply(t2, t1, t2);

	        SecP192R1Field.squareN(t2, 16, t1);
	        SecP192R1Field.multiply(t1, t2, t1);

	        SecP192R1Field.squareN(t1, 32, t2);
	        SecP192R1Field.multiply(t2, t1, t2);

	        SecP192R1Field.squareN(t2, 64, t1);
	        SecP192R1Field.multiply(t1, t2, t1);

	        SecP192R1Field.squareN(t1, 62, t1);
	        SecP192R1Field.square(t1, t2);

//	        System.out.println("T1  " + Nat192.toBigInteger(t1));
//	        System.out.println("T2  " + Nat192.toBigInteger(t2));
	        return Nat192.eq(x1, t2) ? ecspec.getCurve().fromBigInteger(Nat192.toBigInteger(t1)) : null;	    
	}

	private static BigInteger findSquareRootFieldElement(BigInteger x, BigInteger q){

        if (!q.testBit(0))
        {
            throw new RuntimeException("not done yet");
        }

        // note: even though this class implements ECConstants don't be tempted to
        // remove the explicit declaration, some J2ME environments don't cope.

        if (q.testBit(1)) // q == 4m + 3
        {
            BigInteger e = q.shiftRight(2).add(ECConstants.ONE);
            return  x.modPow(e, q);
        }

        if (q.testBit(2)) // q == 8m + 5
        {
//            BigInteger t1 = x.modPow(q.shiftRight(3), q);
//            BigInteger t2 = modMult(t1, x);
//            BigInteger t3 = modMult(t2, t1);
//
//            if (t3.equals(ECConstants.ONE))
//            {
//                return checkSqrt(new Fp(q, r, t2));
//            }
//
//            // TODO This is constant and could be precomputed
//            BigInteger t4 = ECConstants.TWO.modPow(q.shiftRight(2), q);
//
//            BigInteger y = modMult(t2, t4);
//
//            return checkSqrt(new Fp(q, r, y));
        }

        // q == 8m + 1

//        BigInteger legendreExponent = q.shiftRight(1);
//        if (!(x.modPow(legendreExponent, q).equals(ECConstants.ONE)))
//        {
//            return null;
//        }
//
//        BigInteger X = this.x;
//        BigInteger fourX = modDouble(modDouble(X));
//
//        BigInteger k = legendreExponent.add(ECConstants.ONE), qMinusOne = q.subtract(ECConstants.ONE);
//
//        BigInteger U, V;
//        Random rand = new Random();
//        do
//        {
//            BigInteger P;
//            do
//            {
//                P = new BigInteger(q.bitLength(), rand);
//            }
//            while (P.compareTo(q) >= 0
//                || !modReduce(P.multiply(P).subtract(fourX)).modPow(legendreExponent, q).equals(qMinusOne));
//
//            BigInteger[] result = lucasSequence(P, X, k);
//            U = result[0];
//            V = result[1];
//
//            if (modMult(V, V).equals(fourX))
//            {
//                return new ECFieldElement.Fp(q, r, modHalfAbs(V));
//            }
//        }
//        while (U.equals(ECConstants.ONE) || U.equals(qMinusOne));

        return null;
	}
	private static BigInteger findSquareRoot(BigInteger alpha, BigInteger p) {
		BigInteger beta = null;
		if(p.mod(BigInteger.valueOf(4)).compareTo(BigInteger.valueOf(3))== 0){
//			System.out.println("p = 3 mod 4");
//			BigInteger k1 = p.subtract(BigInteger.valueOf(3)).divide(BigInteger.valueOf(4)).mod(p);
			BigInteger k = p.shiftRight(2).add(ONE);
//			System.out.println("p " + Converter.getHex(p.toByteArray()));
//			System.out.println("k " + k.toString());
//			System.out.println("k " + Converter.getHex(k.toByteArray()));
//			System.out.println("k1 " + k1.toString());
//			System.out.println("k1 " + Converter.getHex(k1.toByteArray()));
//			System.out.println("k " + Converter.getHex(k.toByteArray()));
//			System.out.println("k " + Converter.getHex(p.shiftRight(2).toByteArray()));
			beta = alpha.modPow(k,p);
//			System.out.println("p " + Converter.getHex(p.toByteArray()));
//			System.out.println("k " + Converter.getHex(alpha.modPow(BigInteger.valueOf(2),p).toByteArray()));
//			System.out.println("alpha " + alpha.toString());
//			System.out.println("alpha^0203 " + 
//					Converter.getHex(alpha.modPow(
//							new BigInteger(Converter.hexStringToByteArray("03")),p).toByteArray()));
//			System.out.println("fsqrt beta: "+Converter.getHex(beta.toByteArray()));
//			System.out.println("fsqrt alpha: "+alpha.toString());
//			System.out.println("fsqrt beta^2: "+beta.modPow(BigInteger.valueOf(2), p).toString());
		} else if(p.mod(BigInteger.valueOf(8)).compareTo(BigInteger.valueOf(5)) == 0){
			System.out.println("p = 8 mod 5");
			BigInteger k = p.subtract(BigInteger.valueOf(5)).divide(BigInteger.valueOf(8));
			BigInteger gamma = alpha.multiply(BigInteger.valueOf(2)).modPow(k, p);
			BigInteger i = alpha.multiply(BigInteger.valueOf(2)).multiply(gamma.pow(2)).mod(p);
			beta = alpha.multiply(gamma).multiply(i.subtract(ONE)).mod(p);
		} else if(p.mod(BigInteger.valueOf(8)).compareTo(BigInteger.valueOf(1)) == 0){
			beta = null;
			//TODO
			System.out.println("finding square root not fully implemented yet");
		}
		return beta;
	}

	public static BigInteger OS2IP(byte[] _os){
		byte[] _osWithPadding = new byte[_os.length+1];
		System.arraycopy(_os, 0, _osWithPadding, 1, _os.length);
		return new BigInteger(_osWithPadding);
	}
	
	public static ECFieldElement I2FEP(ECParameterSpec _ecspec, BigInteger _i){
		ECFieldElement output = null;
		
		if(_ecspec.getCurve() instanceof AbstractF2m){
			//TODO
		} else{
			output = _ecspec.getCurve().fromBigInteger(_i);
		}
		
		return output;
	}

	public static byte[] GE2OSPX(ECPoint ecPoint){
		byte[] ecPointArray=ecPoint.normalize().getXCoord().getEncoded();
		
		byte[] P0 = new byte[ecPointArray.length+1];
		P0[0] = (byte)0x01;
		
		System.arraycopy(ecPointArray, 0, P0, 1, ecPointArray.length);
		
		return P0; 
	}
	
	public static ECPoint calculateVPi(ECParameterSpec ecSpec, BigInteger U_pi) {
		return ecSpec.getG().multiply(U_pi);
	}
	public static byte[] computeO3(Digest digest,ECPoint W_C, ECPoint W_S ){
		byte[] o1=GE2OSPX(W_C);
		byte[] o2=GE2OSPX(W_S);

		byte[] o3 = new byte[digest.getDigestSize()];
		
		digest.update(o1, 0, o1.length);
		digest.update(o2, 0, o2.length);
		digest.doFinal(o3,0);
		return o3;
	}
	
	public static BigInteger calculateI2(ECParameterSpec ecSpec,Digest digest,ECPoint W_C, ECPoint W_S) {
		return OS2IP(computeO3(digest, W_C, W_S)).mod(ecSpec.getCurve().getField().getCharacteristic());
	}
	
	public static BigInteger calculateI2NoMod(ECParameterSpec ecSpec,Digest digest,ECPoint W_C, ECPoint W_S) {
		byte[] o1=GE2OSPX(W_C);
		byte[] o2=GE2OSPX(W_S);
		byte[] o3 = new byte[digest.getDigestSize()];
		
		digest.update(o1, 0, o1.length);
		digest.update(o2, 0, o2.length);
		
		digest.doFinal(o3,0);
		return OS2IP(o3);
	}
	public static ECPoint calculateE1(ECParameterSpec ecSpec,Digest digest,ECPoint V_pi) {
		byte[] o4=GE2OSPX(V_pi);

		return Redp1(ecSpec,digest,o4);
	}

	public static ECFieldElement SVDPSRP5CLIENT(ECParameterSpec ecSpec,Digest digest, ECPoint W_C, ECPoint W_S, ECPoint V_pi, BigInteger s, BigInteger uPi) {
		BigInteger i2 = calculateI2(ecSpec,digest,W_C,W_S);

		
		ECPoint e1 = calculateE1(ecSpec,digest,V_pi);
		ECPoint e2 = W_S.subtract(e1);
//		System.out.println("E1 " +e1.toString());
//		System.out.println("W_S " +W_S.toString());
//		System.out.println("E2 " +e2.toString());
		ECPoint zG = e2.multiply(s.add(i2.multiply(uPi)));
		
		
		return zG.normalize().getXCoord();
	}

	public static ECFieldElement SVDPSRP5SERVER(ECParameterSpec ecSpec,
			SHA256Digest sha256Digest, ECPoint q_A, ECPoint q_B, ECPoint v_pi,
			BigInteger a, BigInteger u_pi) {
		
		return null;
	}

}
