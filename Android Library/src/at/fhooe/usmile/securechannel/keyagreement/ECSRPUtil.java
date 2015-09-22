package at.fhooe.usmile.securechannel.keyagreement;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

/**
 * Utils for the elliptic curve variant of SRP (SRP-5)
 * @author michaelhoelzl
 *
 */
public class ECSRPUtil {
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
						return computeRandomPoint(ecSpec, digest, i1.add(ONE),++counter);
					} else {
						if(mu == 1){
							y = beta.negate();
						} else if(mu == 0){
							//Do nothing
							y = beta;
						}
						outputE = ecSpec.getCurve().createPoint(x.toBigInteger(), y.toBigInteger());
						outputE = ecSpec.getCurve().validatePoint(x.toBigInteger(), y.toBigInteger());
						if(outputE!=null){
							System.out.println("counter : "+ counter);
							outputE=outputE.multiply(ecSpec.getCurve().getCofactor());
						}
					}
				}
					
			}
		}
		return outputE;
	}
	
	private static BigInteger findSquareRoot(BigInteger alpha, BigInteger p) {
		BigInteger beta = null;
		if(p.mod(BigInteger.valueOf(4)).compareTo(BigInteger.valueOf(3))== 0){
			BigInteger k = p.shiftRight(2).add(ONE);
			beta = alpha.modPow(k,p);
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
		ECPoint zG = e2.multiply(s.add(i2.multiply(uPi)));
		return zG.normalize().getXCoord();
	}

	public static ECFieldElement SVDPSRP5SERVER(ECParameterSpec ecSpec,
			SHA256Digest sha256Digest, ECPoint q_A, ECPoint q_B, ECPoint v_pi,
			BigInteger a, BigInteger u_pi) {
		
		return null;
	}

}
