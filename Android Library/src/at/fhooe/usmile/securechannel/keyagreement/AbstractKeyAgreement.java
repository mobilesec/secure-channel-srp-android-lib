package at.fhooe.usmile.securechannel.keyagreement;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import at.fhooe.usmile.securechannel.CommandApdu;
import at.fhooe.usmile.securechannel.PRNGFixes;

/**
 * @author Endalkachew Asnake, Michael Hölzl
 * 
 */
public abstract class AbstractKeyAgreement implements UsmileKeyAgreement{

	final static short LENGTH_MESSAGE_DIGEST = 0x20;
	final static short LENGTH_RANDOM_NUMBER = (short) 0x10;

	protected final static byte INS_KEYAG_STAGE1 = 0x01;
	protected final static byte INS_KEYAG_STAGE2 = 0x02; 
	protected final static byte INS_KEYAG_STAGE3 = 0x03; 
	protected final static byte INS_CHANGE_PASSWORD = 0x04;

	protected final static byte CLA = (byte) 0x80;
	protected final static byte P1 = 0x00;
	protected final static byte P2 = 0x00;
	protected final static byte LE = 0x00;
	
	protected static final int LENGTH_SALT = 16;
	protected static final int LENGTH_IV = 16;
	
	protected MessageDigest msgDigest_SHA256;
	
	/**
	 * Object for random value generation
	 */
	protected SecureRandom secureRandom;

	/**
	 * shared secret at the end of key agreement
	 */
	protected byte[] mSharedSecret;
	
	/**
	 * Session key computed from shared secret
	 */
	protected byte[] mSessionKey;

	/**
	 * Constructor for key agreement
	 */
	public AbstractKeyAgreement() {
		try { 
			PRNGFixes.apply();
			
			msgDigest_SHA256 = MessageDigest.getInstance("SHA-256"); 
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public byte[] getSessionKey() {
		return mSessionKey;
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
	
	@Override
	public CommandApdu getVerificationCommand(byte[] authData, boolean changePassword) {
		byte p1 = changePassword ? INS_CHANGE_PASSWORD : P1;
		return new CommandApdu(CLA, INS_KEYAG_STAGE3, p1, P2, authData, LE);
	}

	@Override
	public CommandApdu getChangePasswordCommand(byte[] idAndPass) {
		return new CommandApdu(CLA, INS_CHANGE_PASSWORD, P1, P2, idAndPass, LE);
	}
}
