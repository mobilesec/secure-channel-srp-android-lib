package at.fhooe.usmile.securechannel.keyagreement;

import at.fhooe.usmile.securechannel.CommandApdu;

/**
 * Secure channel protocol interface 
 * @author michaelhoelzl
 */
public interface UsmileKeyAgreement {

	/**
	 * Generates own public and private key pair according the used Key Agreement protocol
	 * 
	 * @return client public key A
	 */
	public byte[] init();

	/**
	 * Derives a session key using provided credentials as defined in srp 6a and
	 * computes authentication data to be sent to SE
	 * 
	 * @param externalPublic Applet side public key B
	 * @param identity user identity
	 * @param salt salt received from the Applet
	 * @param password secure channel password
	 * @return authentication Data (M1) of Application side,  null if externalPublic is 0
	 */
	public byte[] computeSessionKey(byte[] externalPublic, byte[] identity,
			byte[] salt, byte[] password);
	

	/**
	 * Authentication: Verifies Authentication Response (M2) received from the Applet side 
	 * 
	 * @param seResponse authentication response from the Applet M2
	 * @return true if authentication is successful, false otherwise
	 */
	public boolean verifySEResponse(byte[] seResponse);
	

	/** 
	 * returns final key derived according to the used protocol
	 * 
	 * @return key buffer
	 */
	public byte[] getSessionKey();

	/**
	 * Get the first stage command which should be sent to the client
	 * @param clientPublicParam
	 * @return
	 */
	public CommandApdu getFirstStageAgreementCommand(byte[] clientPublicParam);
	
	/**
	 * Get the second stage command which should be sent to the client
	 * @param clientPublicParam
	 * @return
	 */
	public CommandApdu getSecondStageAgreementCommand(byte[] clientPublicParam);
	
	/**
	 * Get the verification command. ChangePassword indicates if the following command will be a change password command. 
	 * @param authData
	 * @param changePassword
	 * @return
	 */
	public CommandApdu getVerificationCommand(byte[] authData, boolean changePassword);
	
	/**
	 * Get the change password command for the protocol
	 * @param idAndPass
	 * @return
	 */
	public CommandApdu getChangePasswordCommand(byte[] idAndPass);

	/**
	 * Parse the salt from the response
	 * @param serverPublicParam
	 * @param serverSecondStageResponse
	 * @return Salt
	 */
	public byte[] getSaltFromResponse(byte[] serverPublicParam, byte[] serverSecondStageResponse);
	
	/**
	 * Parse the initialization vector from the response
	 */
	public byte[] getIVFromResponse(byte[] serverIVParam, byte[] serverSecondStageResponse);
	
	/**
	 * Parse the public key from the response
	 * @param serverPublicParam
	 * @param serverSecondStageResponse
	 * @return
	 */
	public byte[] getPublicKeyFromResponse(byte[] serverPublicParam, byte[] serverSecondStageResponse);

}
