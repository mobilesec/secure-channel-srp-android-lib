package at.fhooe.usmile.securechannel.keyagreement;

import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import at.fhooe.usmile.securechannel.Converter;


/**
 * @author Michael Hölzl
 *
 */
public class ECSRP extends AbstractKeyAgreement{

	public final static short LENGTH_MODULUS = (short) 0x18;
	public final static short LENGTH_EC_POINT = (short) (LENGTH_MODULUS * 2 +1);
	
	/*
	 * shared secret at the end of key agreement
	 */
	private ECFieldElement sharedSecret;
	private byte[] K; 

	private byte[] o3; 
	private byte[] iv;
	
	private ECParameterSpec ecSpec;
	private byte[] authData;
	private byte[] publicClient;
	
	private ECPoint Q_A;
	private ECPoint Q_B;
	private ECPoint V_pi;
	private BigInteger U_pi;

	private BigInteger a;

	
	/**
	 * key agreement init
	 */
	public ECSRP() {

	}

	public byte[] init() {
		byte[] aRandom = new byte[32];

		ecSpec = ECNamedCurveTable.getParameterSpec("secp192r1");
		
		generateRandom(aRandom);
		
		a = new BigInteger(1, aRandom);

		Q_A = ecSpec.getG().multiply(a);

		publicClient = Q_A.getEncoded(false);
		if (publicClient.length == 257) {
			publicClient = Arrays.copyOfRange(publicClient, 1, 257);
			 
		}
		return publicClient;
	}

	public byte[] computeSessionKey(byte[] externalPublic, byte[] identity,
			byte[] salt, byte[] password) {
		U_pi = ECSRPUtil.calculateUPi(new SHA256Digest(), ecSpec.getN(), salt,
				identity, password);
		V_pi = ECSRPUtil.calculateVPi(ecSpec,U_pi);

		Q_B = ecSpec.getCurve().decodePoint(externalPublic);

		/**
		 * validate public key and through exception if B.mod(N) = 0
		 */
		sharedSecret = ECSRPUtil.SVDPSRP5CLIENT(ecSpec,new SHA256Digest(), Q_A, Q_B, V_pi, a, U_pi);

		/**
		 * compute K = H(sharedSecret)
		 */
		K = msgDigest_SHA256.digest(sharedSecret.getEncoded());

		/**
		 * compute Authentication data
		 * 
		 * M = H(i2, sharedSecret)
		 */
		o3 = ECSRPUtil.computeO3(new SHA256Digest(), Q_A, Q_B);
		if (o3.length == 33) {
			o3 = Arrays.copyOfRange(o3, 1, 33);
		}
 
 		msgDigest_SHA256.update(o3);
 		authData = msgDigest_SHA256.digest(sharedSecret.getEncoded());
		
		return authData;
	}

	public boolean verifySEResponse(byte[] seResponse) {

		/**
		 * compute expected response from SE
		 */
		msgDigest_SHA256.update(o3); 
		msgDigest_SHA256.update(authData);
		byte[] expectedResponse = msgDigest_SHA256.digest(sharedSecret.getEncoded());
		if (Arrays.equals(seResponse, expectedResponse)) {
			return true;
		} else{
			System.out.println("Expected: " + Converter.getHex(expectedResponse));
			System.out.println("Actual: " + Converter.getHex(seResponse));
			System.err.println("Failed " );
		}
		return false;
	}

	public byte[] getSessionKey() {
		return K;
	}
	public byte[] getIV(){
		return iv;
	}
}
