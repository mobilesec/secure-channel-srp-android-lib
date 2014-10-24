package at.fhooe.usmile.securechannel;

public interface IChannelStatusListener {
	
	/**
	  * A callback method that notifies availability of Smartcard service
	  * 
	  * @param terminals secure element terminals
	  */
	void serviceAvailable(String[] terminals);
	
	/**
	 * A callback method when the key agreement initialization is complete
	 */
	void scInitialized();
	
	/**
	 * A callback method when the secure channel password changing operation is complete
	 */
	public void scPasswordChanged();
 
	/**
	 * A callback method when a mutual authentication phase is complete
	 */
	void scAuthenticated();
	
	/**
	 * A callback method when a secure channel initialization fails
	 * 
	 * @param reason description of the failure if defined or the status word returned from the secure element
	 */
	void scFailed(String reason); 
	
	/**
	 * A callback method when the secure channel is blocked (after 5 wrong password inputs)
	 * currently there is no means of unblocking the channel
	 */
	void scBlocked(); 
	
	/**
	 * not applicable currently (to terminate the use of the secure channel if unblocking from blocked state is available
	 */
	void scTerminated();

	 
	
}