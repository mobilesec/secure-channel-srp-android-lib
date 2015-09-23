package at.fhooe.usmile.securechannel.keyagreement;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import at.fhooe.usmile.securechannel.CommandApdu;
import at.fhooe.usmile.securechannel.Converter;


/**
 * This is an implementation of the elliptic curve variant of the Secure Remote
 * Password (SRP-5) password-authenticated secure channel protocol from IEEE Std
 * 1363.2-2008.
 * 
 * This implementation uses the elliptic curve secp192k1. For the usage of
 * another elliptic curve, the applet implementation needs to be adapted.
 * 
 * @author Michael Hölzl
 */
public class ECSRP extends AbstractKeyAgreement{

	public final static short LENGTH_MODULUS = (short) 0x18;
	public final static short LENGTH_EC_POINT = (short) (LENGTH_MODULUS * 2 +1);
	
	/**
	 * Used EC parameters
	 */
	private ECParameterSpec mECSpec;
	
	/**
	 * Authentication data sent to server
	 */
	private byte[] mAuthData;
	
	/**
	 * Public keys
	 */
	private ECPoint Q_A;
	private ECPoint Q_B;

	/**
	 * Private key
	 */
	private BigInteger d_A;

	/**
	 * Password derived points
	 */
	private ECPoint V_pi;
	private BigInteger x;

	/**
	 * Random scrambling parameter derived from the x-coordinates of the public keys
	 */
	private byte[] u; 

	@Override
	public byte[] init() {
		byte[] aRandom = new byte[32];

		mECSpec = ECNamedCurveTable.getParameterSpec("secp192r1");
		
		generateRandom(aRandom);
		
		d_A = new BigInteger(1, aRandom);

		Q_A = mECSpec.getG().multiply(d_A);

		byte[] publicClient = Q_A.getEncoded(false);
		if (publicClient.length == 257) { //Assure that no additional 0 was added
			publicClient = Arrays.copyOfRange(publicClient, 1, 257);
		}
		return publicClient;
	}

	@Override
	public byte[] computeSessionKey(byte[] externalPublic, byte[] identity,
			byte[] salt, byte[] password) {
		x = ECSRPUtil.calculateUPi(new SHA256Digest(), mECSpec.getN(), salt,
				identity, password);
		V_pi = ECSRPUtil.calculateVPi(mECSpec,x);

		Q_B = mECSpec.getCurve().decodePoint(externalPublic);

		/**
		 * validate public key and through exception if B.mod(N) = 0
		 */
		mSharedSecret = ECSRPUtil.SVDPSRP5CLIENT(mECSpec,new SHA256Digest(), Q_A, Q_B, V_pi, d_A, x).getEncoded();

		/**
		 * compute K = H(sharedSecret)
		 */
		mSessionKey = msgDigest_SHA256.digest(mSharedSecret);

		/**
		 * compute Authentication data
		 * (u equals o3 in IEEE 1363.2-2008.)
		 * M = H(u, sharedSecret)
		 */
		u = ECSRPUtil.computeO3(new SHA256Digest(), Q_A, Q_B);
		if (u.length == 33) {
			u = Arrays.copyOfRange(u, 1, 33);
		}
 
 		msgDigest_SHA256.update(u);
 		mAuthData = msgDigest_SHA256.digest(mSharedSecret);
		
		return mAuthData;
	}

	@Override
	public boolean verifySEResponse(byte[] seResponse) {

		/**
		 * compute expected response from SE
		 */
		msgDigest_SHA256.update(u); 
		msgDigest_SHA256.update(mAuthData);
		byte[] expectedResponse = msgDigest_SHA256.digest(mSharedSecret);
		if (Arrays.equals(seResponse, expectedResponse)) {
			return true;
		} else{
			System.out.println("Expected: " + Converter.getHex(expectedResponse));
			System.out.println("Actual: " + Converter.getHex(seResponse));
			System.err.println("Failed " );
		}
		return false;
	}

	@Override
	public CommandApdu getFirstStageAgreementCommand(byte[] clientPublicParam) {
		return new CommandApdu(CLA, INS_KEYAG_STAGE1, P1, P2,
				clientPublicParam, LE);
	}

	@Override
	public CommandApdu getSecondStageAgreementCommand(byte[] clientPublicParam) {
		return null;
	}

	@Override
	public byte[] getSaltFromResponse(byte[] serverPublicParam, byte[] serverSecondStageResponse) {
		if (serverPublicParam.length < LENGTH_EC_POINT + LENGTH_SALT)
			return null;
		
		return Arrays.copyOfRange(serverPublicParam,
				LENGTH_EC_POINT, LENGTH_EC_POINT + LENGTH_SALT);
	}

	@Override
	public byte[] getIVFromResponse(byte[] serverPublicParam, byte[] serverSecondStageResponse) {
		if (serverPublicParam.length < LENGTH_EC_POINT + LENGTH_SALT + LENGTH_IV)
			return null;
		
		return Arrays.copyOfRange(serverPublicParam,
				LENGTH_EC_POINT + LENGTH_SALT, LENGTH_EC_POINT
				+ LENGTH_SALT + LENGTH_IV);
	}

	@Override
	public byte[] getPublicKeyFromResponse(byte[] serverPublicParam, byte[] serverSecondStageResponse) {
		if (serverPublicParam.length < LENGTH_EC_POINT)
			return null;
		
		return Arrays.copyOfRange(serverPublicParam,
				0, LENGTH_EC_POINT);
	}


}
