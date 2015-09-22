package at.fhooe.usmile.securechannel.keyagreement;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author Endalkachew Asnake
 * 
 */
public abstract class AbstractKeyAgreement implements UsmileKeyAgreement{

	final static short LENGTH_MESSAGE_DIGEST = 0x20;

	final static short LENGTH_RANDOM_NUMBER = (short) 0x10;

	protected MessageDigest msgDigest_SHA256;
	protected SecureRandom secureRandom;

	/*
	 * shared secret at the end of key agreement
	 */
	protected byte[] sharedSecret;
	protected byte[] K;

	/**
	 * Constructor for key agreement
	 */
	public AbstractKeyAgreement() {

		try { 
			msgDigest_SHA256 = MessageDigest.getInstance("SHA-256"); 
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public byte[] getSessionKey() {
		return K;
	}

	/**
	 * generates secure random
	 * 
	 * @param random initialized byte array buffer to be filled with random bytes
	 * @return true 
	 */
	protected boolean generateRandom(byte[] random) {
		secureRandom = new SecureRandom();
		secureRandom.nextBytes(random);
		return true;
	}

	/**
	 * Performs a zero padding to the left of the input
	 * 
	 * @param input byte array buffer to be padded
	 * @param outputLength length of the final output
	 * @return zero padded input if input length is less that outputLength, if not  returns the input itself
	 */
	protected byte[] getLeftZeroPadded(byte[] input, int outputLength) {
		byte[] output = new byte[outputLength];
		if (input.length >= outputLength) {
			return input;
		} else {
			System.arraycopy(input, 0, output, outputLength - input.length,
					input.length);
		}
		return output;

	}
}
