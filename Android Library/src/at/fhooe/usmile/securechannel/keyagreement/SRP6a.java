package at.fhooe.usmile.securechannel.keyagreement;

import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.Cipher;

import at.fhooe.usmile.securechannel.Converter;

public class SRP6a extends AbstractKeyAgreement{

	private static final byte[] N_2048 = Converter
			.hexStringToByteArray("AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73");
	private static final byte[] g_2048 = new byte[]{0x02};

	private static BigInteger k;

	private static final BigInteger g = new BigInteger(1, g_2048);

	private static final BigInteger N = new BigInteger(1, N_2048);

	private byte[] uBytes;
	
	private BigInteger a;
	private BigInteger A;
	private BigInteger B;
	private BigInteger U;
	private BigInteger X;
	private BigInteger S;

	byte[] authData;
	byte[] publicClient;
	public SRP6a(){
		/**
		 * compute k = H(N,g)
		 */
		msgDigest_SHA256.update(N_2048);

		byte[] padded_g = getLeftZeroPadded(g_2048, N_2048.length);

		byte[] k_2048 = msgDigest_SHA256.digest(padded_g);
		
		k = new BigInteger(1, k_2048);
	}
	
	public byte[] init() {
		byte[] aRandom = new byte[32];
		generateRandom(aRandom);
		a = new BigInteger(1, aRandom);
		A = g.modPow(a, N);
	 
		publicClient = A.toByteArray();
		if (publicClient.length == 257) {
			publicClient = Arrays.copyOfRange(publicClient, 1, 257);

		}
		return publicClient;
	}

	public byte[] computeSessionKey(byte[] externalPublic, byte[] identity,
			byte[] salt, byte[] password) {

		B = new BigInteger(1, externalPublic);

		/**
		 * validate public key and through exception if B.mod(N) = 0
		 */

		if (B.mod(N) == BigInteger.ZERO) {
			return null;
		}

		/**
		 * compute U = H(A,B)
		 */
		msgDigest_SHA256.update(publicClient);
		U = new BigInteger(1, msgDigest_SHA256.digest(externalPublic));
		 

		/**
		 * compute X = H(S, H(identity:password)) .... from Bouncycastle SRP6
		 * implementation
		 */
		msgDigest_SHA256.update(identity);
		msgDigest_SHA256.update(":".getBytes());
		byte[] temp = msgDigest_SHA256.digest(password);
		msgDigest_SHA256.update(salt);
		X = new BigInteger(1, msgDigest_SHA256.digest(temp));

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
		K = msgDigest_SHA256.digest(sharedSecret);

		/**
		 * compute Authentication data
		 * 
		 * M = H(uBytes, sharedSecret)
		 */
		uBytes = U.toByteArray();
		if (uBytes.length == 33) {
			uBytes = Arrays.copyOfRange(uBytes, 1, 33);
		}

		msgDigest_SHA256.update(uBytes);
		authData = msgDigest_SHA256.digest(sharedSecret);

		return authData;

	}

	public boolean verifySEResponse(byte[] seResponse) {

		/**
		 * compute expected response from SE
		 */
		msgDigest_SHA256.update(uBytes);
		msgDigest_SHA256.update(authData);
		byte[] expectedResponse = msgDigest_SHA256.digest(sharedSecret);

		if (Arrays.equals(seResponse, expectedResponse)) {
			return true;
		} else {
			return false;
		}

	}

}
