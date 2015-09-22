package at.fhooe.usmile.securechannel;



import java.io.IOException;

import org.simalliance.openmobileapi.Channel;
import org.simalliance.openmobileapi.Reader;
import org.simalliance.openmobileapi.SEService;
import org.simalliance.openmobileapi.Session;

import android.content.Context;
import android.util.Log;
import android.widget.Toast;
/**
 * @author Endalkachew Asnake
 *
 */
class SEConnection implements SEService.CallBack {

	static public SEService seService;
	private Reader reader = null;
 	private Reader[] readers;
	Channel channel ;
	byte[] AID;
	String[] readerList ;
 
	
	long elapsedTime = 0L;
	
	Context appContext;
	private ISEServiceStatusListener mListener;
	
	
	/**
	 * Constructor for Secure Element Connection
	 * 
	 * @param context application context
	 * @param listener connection service status listener
	 */
	public SEConnection(Context context, ISEServiceStatusListener listener ){		
		try{
			appContext = context;
			
			mListener = listener;
		 
			seService = new SEService(appContext.getApplicationContext(), this);
			
			
		  } catch (SecurityException e) {
			    Log.e("Security Exception", "Binding not allowed, uses-permission org.simalliance.openmobileapi.SMARTCARD?");
		} catch (Exception e) {
			    Log.e("Exception: " ,e.getMessage());
		}
	}
	
 /**
  * closes the connection to the secure element
  */
	public void closeConnection(){
		 if (seService != null && seService.isConnected()) {
		      seService.shutdown();
		      Log.i("Connection ", "SE Connection Closed");		 
		 }
	}
	
 
	@Override
	public void serviceConnected(SEService arg0) {
		// TODO Auto-generated method stub
		readers = seService.getReaders();
		readerList = new String[readers.length];
		int i = 0;
		for(Reader r : readers){
			Log.i("reader " , r.getName());
			readerList[i] = r.getName();
			i += 1;
		}
		//if(selectApplet(AID, 0)){
	 	 mListener.seServiceAvailable(readerList);
	 	//}
	}
	
	/**
	 * Selects an Applet with the specified Applet id (aid) and reader specified by readerIndex 
	 * 
	 * @param aid Applet ID
	 * @param readerIndex index of the terminal that the secure element is connected to
	 * @return true if Applet selection is successful, false otherwise
	 */
	public boolean selectApplet(byte[] aid, int readerIndex){
		
		if (readers.length > 0 ){
			reader = readers[readerIndex];
		    Session session;
			try {
				session = reader.openSession();
			    channel = session.openLogicalChannel(aid); 
			    return true;
			} catch (Exception ex) {
				ex.printStackTrace();
			}
	    
		}
		return false;
	}
	
	/**
	 * Sends the command buffer to the applet currently selected
	 * 
	 * @param cmdApdu ISO/IEC 7816-4 Command APDU buffer
	 * @return ISO/IEC 7816-4 Response APDU buffer
	 */
	public byte[] sendCommand(byte[] cmdApdu){
		if(!channel.isClosed()){
	    	byte[] respApdu = new byte[0];
			
	    	try {
				
				long commandTime = 0L;
				long responseTime = 0L;
				commandTime = System.nanoTime();
				respApdu = channel.transmit(cmdApdu);
				responseTime = System.nanoTime();
				elapsedTime = responseTime - commandTime;
				
			 				 
			} catch (IOException e) {
				// TODO Auto-generated catch block
				Toast.makeText(appContext.getApplicationContext(), e.getMessage(), Toast.LENGTH_SHORT).show();
			}
	    	return respApdu;
		}
		return null;
	}
	
	/**
	 * returns the response time of the secure element of the immediate 
	 * Command-Response exchange before this method call
	 * 
	 * @return Response time with nano second precision
	 */
	public long getElapsedTime(){
		return elapsedTime;
	}

}
