package at.fhooe.usmile.securechannel;

 public interface ISEServiceStatusListener {
	 /**
	  * A callback method that notifies availability of Smartcard service
	  * 
	  * @param terminals secure element terminals
	  */
	public void seServiceAvailable(String[] terminals);
	 
}
