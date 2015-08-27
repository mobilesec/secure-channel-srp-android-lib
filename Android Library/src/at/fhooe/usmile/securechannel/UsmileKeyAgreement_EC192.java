package at.fhooe.usmile.securechannel;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;


/**
 * @author Endalkachew Asnake
 *
 */
class UsmileKeyAgreement_EC192 {
 

	public final static short LENGTH_MODULUS = (short) 0x18;
	public final static short LENGTH_EC_POINT = (short) (LENGTH_MODULUS * 2 +1);

	private MessageDigest msgDigest_SHA256;
	final static short LENGTH_MESSAGE_DIGEST = 0x20;

	private Cipher aesCipher;
	
	final static short LENGTH_RANDOM_NUMBER = (short) 0x10;
	SecureRandom secureRandom;

	/*
	 * shared secret at the end of key agreement
	 */
	ECFieldElement sharedSecret;
	byte[] K; 

	byte[] o3; 
	byte[] iv;
//	private static  BigInteger k;  
	
	PublicKey externalPublicKey;

	KeyFactory keyFactory; 

	ECParameterSpec ecSpec;
//	private static final BigInteger g = new BigInteger(1, Hex.decode("02"));

//	private static final BigInteger N = new BigInteger(
//			1,
//			Hex.decode("AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"));
	
	
	//Elliptic curve secp192r1
//	private static final BigInteger G = new BigInteger(
//			1,Hex.decode("04 188DA80E B03090F6 7CBF20EB 43A18800 F4FF0AFD 82FF1012 07192B95 FFC8DA78 631011ED 6B24CDD5 73F977A1 1E794811"));
//
//	private static final BigInteger a = new BigInteger(
//			1,Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"));
//	private static final BigInteger b = new BigInteger(
//			1,Hex.decode("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1"));
//	private static final BigInteger S = new BigInteger(
//			1,Hex.decode("3045AE6FC8422F64ED579528D38120EAE12196D5"));
//
//	private static final BigInteger p = new BigInteger(
//			1,Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"));
	private static final BigInteger n = new BigInteger(
			1,Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"));
//	
//	private static final int h = 1;
	
	
	byte[] authData;
	byte[] publicClient;


	
	private ECPoint Q_A;
	private ECPoint Q_B;

	private ECPoint V_pi;
	
	private BigInteger U_pi;

	private BigInteger a;

	
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	/**
	 * key agreement init
	 */
	public UsmileKeyAgreement_EC192() {

		try {

			msgDigest_SHA256 = MessageDigest.getInstance("SHA-256");
//			k = SRP6Util.calculateK(new SHA256Digest(), N, g);
			
		 
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  

	}

	/**
	 * Generates own public and private key pair according to SRP 6a
	 * @return
	 */
	public byte[] initWithSRP() {
		byte[] aRandom = new byte[32];

		ecSpec = ECNamedCurveTable.getParameterSpec("secp192r1");
		
		generateRandom(aRandom);
		a = new BigInteger(1, aRandom);
		

//		System.out.println("private " + Converter.getHex(a.toByteArray()));
		Q_A = ecSpec.getG().multiply(a);

		publicClient = Q_A.getEncoded(false);
		if (publicClient.length == 257) {
			publicClient = Arrays.copyOfRange(publicClient, 1, 257);
			 
		}
		return publicClient;
	}

	/**
	 * Drives a session key using provided credentials as defined in srp 6a 
	 * and computes authentication data to be sent to SE
	 * 
	 * @param externalPublic
	 * @param identity
	 * @param salt
	 * @param password
	 * @return
	 */
	public byte[] computeSessionKey(byte[] externalPublic, byte[] identity,
			byte[] salt, byte[] password) {


//		BigInteger Q_Bx = new BigInteger(Arrays.copyOfRange(externalPublic, 1, LENGTH_PUPLIC_PARAM+1));
//		BigInteger Q_By = new BigInteger(Arrays.copyOfRange(externalPublic, LENGTH_PUPLIC_PARAM+1, LENGTH_PUPLIC_PARAM*2+1));
		U_pi = SRP5Util.calculateUPi(new SHA256Digest(), ecSpec.getN(), salt,
				identity, password);
		
//		System.out.println("Calculated Upi: "+ Converter.getHex(U_pi.toByteArray()));
		
		V_pi = SRP5Util.calculateVPi(ecSpec,U_pi);
		
//		System.out.println("Calculated Vpi: "+ Converter.getHex(V_pi.getEncoded(false)));

		Q_B = ecSpec.getCurve().decodePoint(externalPublic);
		
//		System.out.println("EC Curve G: "+ Converter.getHex(ecSpec.getG().getEncoded(false)));
//		System.out.println("EC Curve G-X: "+ ecSpec.getG().getXCoord().toString());
//		System.out.println("EC Curve G-X: "+ ecSpec.getG().getYCoord().toString());
//		System.out.println("EC Curve H: "+ Converter.getHex(ecSpec.getH().toByteArray()));
//		System.out.println("EC Curve N: "+ Converter.getHex(ecSpec.getN().toByteArray()));
//		System.out.println("EC Curve Seed: "+ Converter.getHex(ecSpec.getSeed()));
//		System.out.println("EC Curve order: "+ Converter.getHex(ecSpec.getCurve().getOrder().toByteArray()));
//		System.out.println("EC Curve cofactor: "+ Converter.getHex(ecSpec.getCurve().getCofactor().toByteArray()));
//		System.out.println("EC Curve field size: "+ (ecSpec.getCurve().getFieldSize()));
//		System.out.println("EC Curve dimension: "+ ecSpec.getCurve().getField().getDimension());
//		System.out.println("EC Curve 2: "+ Converter.getHex(BigInteger.valueOf(2).toByteArray()));
//		System.out.println("EC Curve Characteristics: "+ Converter.getHex(ecSpec.getCurve().getField().getCharacteristic().toByteArray()));
//		System.out.println("EC Curve Characteristics: "+ ecSpec.getCurve().getField().getCharacteristic());
//		System.out.println("EC Curve Seed: "+ n.toString());

//		if(Q_B.isValid()){
//			System.out.println("Valid public key from server" + Q_B);
//			
//			System.out.println(" G times x " + Converter.getHex(Q_B.multiply(a).getEncoded(false)));
//		} else {
//			System.out.println("INVALID public key from server");
//		}
		/**
		 * validate public key and through exception if B.mod(N) = 0
		 */
		
//		if(Q_B.mod(n) == BigInteger.ZERO){
//			return null;
//		}

		
		sharedSecret = SRP5Util.SVDPSRP5CLIENT(ecSpec,new SHA256Digest(), Q_A, Q_B, V_pi, a, U_pi);
//		System.out.println("Calculated Z: "+ Converter.getHex(sharedSecret.toBigInteger().toByteArray()));
		
//		U = SRP6Util.calculateU(new SHA256Digest(), N, A, B);
//		X = SRP6Util.calculateX(new SHA256Digest(), N, salt,
//				identity, password);
/*
		V_pi = 
		BigInteger exp = U.multiply(X).mod(N).add(a).mod(N);
		BigInteger tmp = g.modPow(X, N).multiply(k).mod(N);

		S = B.mod(N).subtract(tmp).mod(N).modPow(exp, N);

		sharedSecret = S.toByteArray();
		if (sharedSecret.length == 257) {
			sharedSecret = Arrays.copyOfRange(sharedSecret, 1, 257);
		}
		
		/**
		 * compute K = H(sharedSecret)
		 */
		K = msgDigest_SHA256.digest(sharedSecret.getEncoded());
		
//		iv = msgDigest_SHA256.digest(Arrays.copyOf(sharedSecret, 16));

//		System.out.println("K " +Converter.getHex(K));
		
		/**
		 * compute Authentication data
		 * 
		 * M = H(i2, sharedSecret)
		 */
		o3 = SRP5Util.computeO3(new SHA256Digest(), Q_A, Q_B);
		if (o3.length == 33) {
			o3 = Arrays.copyOfRange(o3, 1, 33);
		}
 
 		msgDigest_SHA256.update(o3);
 		authData = msgDigest_SHA256.digest(sharedSecret.getEncoded());
		
//		authData=Q_B.multiply(a).getEncoded(false);
		return authData;

	}

	/**
	 * Verifies Response received from SE
	 * 
	 * @param seResponse
	 * @return
	 */
	public boolean verifySEResponse(byte[] seResponse) {

		/**
		 * compute expected response from SE
		 */

//        System.out.println("o3  " +Converter.getHex(o3));
//        System.out.println("SS  " +Converter.getHex(sharedSecret.getEncoded()));
//        System.out.println("Auth  " +Converter.getHex(authData));
		msgDigest_SHA256.update(o3); 
		msgDigest_SHA256.update(authData);
		byte[] expectedResponse = msgDigest_SHA256.digest(sharedSecret.getEncoded());

//        System.out.println("Actual Response: " +Converter.getHex(seResponse));
//        System.out.println("Expected:        " +Converter.getHex(expectedResponse));
		if (Arrays.equals(seResponse, expectedResponse)) {
			return true;
		} else{
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

 /**
  * 
  * @param random
  * @return
  */
	private boolean generateRandom(byte[] random) {
		secureRandom = new SecureRandom();
		secureRandom.nextBytes(random);
		return true;
	}
}
