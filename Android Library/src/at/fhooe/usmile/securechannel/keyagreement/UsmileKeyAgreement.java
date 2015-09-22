package at.fhooe.usmile.securechannel.keyagreement;



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
}
