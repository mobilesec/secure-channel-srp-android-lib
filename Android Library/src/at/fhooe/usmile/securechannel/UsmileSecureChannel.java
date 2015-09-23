package at.fhooe.usmile.securechannel;

import android.content.Context;
import android.os.Handler;
import android.util.Log;
import at.fhooe.usmile.securechannel.keyagreement.ECSRP;
import at.fhooe.usmile.securechannel.keyagreement.SRP6a;
import at.fhooe.usmile.securechannel.keyagreement.UsmileKeyAgreement;

/**
 * @author Endalkachew Asnake
 *
 */
public class UsmileSecureChannel implements ISEServiceStatusListener{

	private final static String STATUS_CONNECTED = "9000";
	private final static String STATUS_INITIALIZED = "1000";
	private final static String STATUS_BLOCKED = "0100";
	private final static String STATUS_TERMINATED = "0f00";
	private final static String STATUS_SELECTION_FAILED = "0110";
	private final static String STATUS_AUTH_FAILED_FROM_SE = "0120";
	private final static String STATUS_AUTH_FAILED_FROM_APP = "0130";
	private final static String STATUS_PASSWORD_CHANGED = "0104";
	private final static String STATUS_PASSWORD_CHANGE_FAILED = "0105";
	private final static String STATUS_PASSWORD_SHORT = "0106";

	private final static int MIN_PASSWORD_LENGTH = 6;
	
	public enum KEYAGREEMENT_PROTOCOL {
		KEYAGREEMENT_SRP6a,
		KEYAGREEMENT_ECSRP,
	}

	private UsmileKeyAgreement usmileKeyAgreement;
	private SecureMessaging usmileSecureMessaging;
	private boolean sessionSecure;
	private byte[] mPassword;
	private byte[] mNewPassword;
	private byte[] mNewUserID;

	private SEConnection seConnection;
	private byte[] AID;
	private CommandApdu cmdApdu;
	private ResponseApdu respApdu;
	private Thread initThread;
	private Thread authThread;
	private Handler handler = new Handler();

	private byte[] incomingPublicParam ;
	private byte[] salt;
	private byte[] iv;
	private String SW;
	
	
	
	//ChannelStatusListener channelSatusListener;
	private IChannelStatusListener channelSatusListener;

	////////////////////////** for performance measurement *//////////////////////////
	private long starttime = 0L;
	private long endtime = 0L;
	
	private long step1SEresponseTime = 0L;
	private long step2SEresponseTime = 0L;
	 	 
	private long overAllKeyAgreementElapsedTime = 0L;
	private int selectedReader;
	private byte[] mUserID;
	
	private KEYAGREEMENT_PROTOCOL mAgreementProtocol;
 	
	/**
	 * Returns secure element response time for the initialization of the key agreement
	 * 
	 * @return  response time with nano second precision 
	 */
	public long getResponseTimeKeyAgreementInit(){
		return step1SEresponseTime;
	}
	
	/**
	 * Returns secure element response time for authentication phase
	 * 
	 * @return response time with nano second precision
	 */
	public long getResponseTimeAuthentication(){
		return step2SEresponseTime;
	}
 
	/**
	 * Returns overall time required for secure channel initialization, 
	 * including time required by the application side
	 * 
	 * @return overall time with nano second precision
	 */
	public long getOverallTime(){
		return overAllKeyAgreementElapsedTime;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Constructor
	 * 
	 * @param context Application context
	 * @param listener secure channel status listener object
	 */
	public UsmileSecureChannel(Context context,
			IChannelStatusListener listener) {
		
		seConnection = new SEConnection(context, this); 
		channelSatusListener = listener;
	}

	/**
	 * Method to check that the secure channel session is successfully initialized
	 * 
	 * @return true if secure channel session is secure, false otherwise
	 */
	public boolean isSessionSecure() {
		return sessionSecure;
	}

	/**
	 * Initializes the secure channel connection with the Applet specified by appletID and
	 *  Secure element specified by  readerIndex  
	 *  
	 *  <p> This method has a long running task. When the long running task completes 
	 *  the secure channel status listener is notified with a callback method <code>ISEServiceStatusListener.scInitialized()</code>
	 *  
	 * @param appletID Applet ID
	 * @param readerIndex index of the terminal that the secure element is connected to
	 */
	public void initConnection(byte[] appletID, int readerIndex, KEYAGREEMENT_PROTOCOL protocol){
		
		AID = appletID;
		selectedReader = readerIndex;
		mAgreementProtocol = protocol;
		
		initKeyAgreement(mAgreementProtocol);
		
		initThread = new Thread() {
			public void run() {
				
				if(seConnection.selectApplet(AID, selectedReader)){
					/**
					 * send 255 as data and last byte as LE
					 */
					runKeyAgreement();
				}else{
					SW = STATUS_SELECTION_FAILED;
				}
				

				handler.post(submitToCallBackListener);
			}
		};
		initThread.start();
	}

    /**
     * executes complete key agreement process
     *
     * @param passwordBytes
     * @return 
     */
    private void runKeyAgreement() {
		byte[] serverSecondStageResponse = null, serverInitSRPResponse = null;
    	starttime = System.nanoTime();
    	
        byte[] publicThis = usmileKeyAgreement.init();
        System.out.println("client initialization " + (System.nanoTime()-starttime)/1000);
        
        /**
         * send public key in first stage
         */
        cmdApdu = usmileKeyAgreement.getFirstStageAgreementCommand(publicThis);

        ResponseApdu respApdu = new ResponseApdu(seConnection.sendCommand(cmdApdu.getApduBuffer()));
        
		step1SEresponseTime = seConnection.getElapsedTime() / 1000;

        serverInitSRPResponse = respApdu.getData();
        
        if (respApdu.statusOk()) 
        {
			/**
			 * request second stage result (e.g. salt byte[] in SRP-6a) Arrays.copyOfRange(respApdu, 16, 144)
			 */
			cmdApdu =  usmileKeyAgreement.getSecondStageAgreementCommand(publicThis);
			
			if(cmdApdu != null){
				respApdu = new ResponseApdu(seConnection.sendCommand(cmdApdu.getApduBuffer()));
				serverSecondStageResponse = respApdu.getData();
				step2SEresponseTime = step2SEresponseTime + seConnection.getElapsedTime() / 1000;

				if( !respApdu.statusOk()){
					SW = STATUS_AUTH_FAILED_FROM_SE;
				} 
			}

			if(SW != STATUS_AUTH_FAILED_FROM_SE){
				incomingPublicParam = usmileKeyAgreement.getPublicKeyFromResponse(serverInitSRPResponse, serverSecondStageResponse);
				salt = usmileKeyAgreement.getSaltFromResponse(serverInitSRPResponse, serverSecondStageResponse);
				iv = usmileKeyAgreement.getIVFromResponse(serverInitSRPResponse, serverSecondStageResponse);
	
				SW = STATUS_INITIALIZED;
			}
        } else {
            System.out.println("failed : " + Converter.getHex(respApdu.getSW()));
            SW = STATUS_AUTH_FAILED_FROM_SE;		
        }
    }

	
	private void initKeyAgreement(KEYAGREEMENT_PROTOCOL protocol) {
		switch(protocol){
		case KEYAGREEMENT_ECSRP:
			usmileKeyAgreement = new ECSRP();
			break;
		case KEYAGREEMENT_SRP6a:
		default:
			usmileKeyAgreement = new SRP6a();
			break;
		}
	}

	/**
	 * Changes userID and password based on the specified parameters. 
	 * This method can be called only after the long running task of initConnection method is completed 
	 * 
	 * <p> This method does not check previous current values of userID and password. 
	 * If only change of password is desired, userID and newUserID should have the same value
	 * 
	 * <p> This method has a long running task. When the long running task completes 
	 *   the secure channel status listener is notified with a callback method <code>IChannelStatusListener.passwordChanged()</code> 
	 *  
	 * @param userID the current user ID
	 * @param newUserID a new user ID or current user ID
	 * @param password the current password
	 * @param newPassword a new password or current password
	 */
	public void changePasswordandUserID(byte[] userID, byte[] newUserID, byte[] password, byte[] newPassword){
		mPassword = password;
		mUserID = userID;
		mNewPassword = newPassword;
		mNewUserID = newUserID;
			 
		authThread = new Thread() {
			public void run(){
		 	
				if(mNewPassword.length < MIN_PASSWORD_LENGTH){
					SW = STATUS_PASSWORD_SHORT;
					handler.post(submitToCallBackListener);
					return;
				}
				
				byte[] authData = usmileKeyAgreement.computeSessionKey(incomingPublicParam, mUserID, salt, mPassword);
				
 				cmdApdu = usmileKeyAgreement.getVerificationCommand(authData, true);
				byte[] responseBuffer = seConnection.sendCommand(cmdApdu.getApduBuffer());
				respApdu = new ResponseApdu(responseBuffer);
				
				step2SEresponseTime = seConnection.getElapsedTime() / 1000;
 				
				if(respApdu.statusOk()){
					 
					if(usmileKeyAgreement.verifySEResponse(respApdu.getData())){
						sessionSecure = true;
						usmileSecureMessaging = new SecureMessaging(usmileKeyAgreement.getSessionKey(), iv);

						byte[] id_3a_pass = Converter.concatArray(mNewUserID, new byte[]{0x3A});
						id_3a_pass = Converter.concatArray(id_3a_pass, mNewPassword);
						
						cmdApdu = usmileKeyAgreement.getChangePasswordCommand(id_3a_pass);
						
						responseBuffer = encodeAndSend( cmdApdu);
						respApdu = new ResponseApdu(responseBuffer);
						
						if(respApdu.statusOk()){
							SW = STATUS_PASSWORD_CHANGED;
						}else{
							SW = STATUS_PASSWORD_CHANGE_FAILED;
						}  	
					}else{
						Log.i("uschannel ", "from device authentication failed ");
						SW = STATUS_AUTH_FAILED_FROM_APP;						
					}
				}else{
					Log.i("uschannel ", "from card authentication failed ");
					SW = STATUS_AUTH_FAILED_FROM_SE;
				}
				handler.post(submitToCallBackListener);
			}
		};
		authThread.start();
	}
	
	/**
	 * Performs authentication using the specified userID and password, 
	 * and initializes the secure channel session. 
	 * Can be called only after the long running task of initConnection method is completed 
	 *  
	 * <p> This method has a long running task. When the long running task completes 
	 *   the secure channel status listener is notified with a callback method <code>IChannelStatusListener.scInitialized()</code>
	 *    
	 * @param userID  user ID
	 * @param password password
	 */
	public void authenticate(byte[] userID, byte[] password){
		mPassword = password;
		mUserID = userID;
		authThread = new Thread() {
			public void run() {
				byte[] authData = usmileKeyAgreement.computeSessionKey(incomingPublicParam, mUserID, salt, mPassword);

				cmdApdu = usmileKeyAgreement.getVerificationCommand(authData, false);
 				
				byte[] responseBuffer = seConnection.sendCommand(cmdApdu.getApduBuffer());
				respApdu = new ResponseApdu(responseBuffer);
				
				step2SEresponseTime = seConnection.getElapsedTime() / 1000;
 				
				if(respApdu.statusOk()){
					 
					if(usmileKeyAgreement.verifySEResponse(respApdu.getData())){
						sessionSecure = true;
						usmileSecureMessaging = new SecureMessaging(usmileKeyAgreement.getSessionKey(), iv);
						endtime = System.nanoTime(); 	
						overAllKeyAgreementElapsedTime = (endtime - starttime) / 1000;
 
						SW = STATUS_CONNECTED;
					}else{
						Log.i("uschannel ", "from device authentication failed ");
						SW = STATUS_AUTH_FAILED_FROM_APP;						
					}
				}else{
					Log.i("uschannel ", "from card authentication failed ");
					SW = STATUS_AUTH_FAILED_FROM_SE;
				}
				handler.post(submitToCallBackListener);
			}

		};
		authThread.start();
		
	}
	
	/**
	 * Closes the secure channel 
	 */
	public void closeSession() {
		sessionSecure = false;
		seConnection.closeConnection();
	}

	/**
	 * 
	 */
	private Runnable submitToCallBackListener = new Runnable() {

		@Override
		public void run() {
			// TODO Auto-generated method stub
			if (SW.equals(STATUS_CONNECTED)) {
				channelSatusListener.scAuthenticated();
			} else if(SW.equals(STATUS_INITIALIZED)){
				channelSatusListener.scInitialized();
			}else if (SW.equals(STATUS_BLOCKED)) {
				channelSatusListener.scBlocked();
			} else if (SW.equals(STATUS_TERMINATED)) {
				channelSatusListener.scTerminated();
			} else if (SW.equals(STATUS_SELECTION_FAILED)){
				channelSatusListener.scFailed("Applet Selection Failed");
			} else if (SW.equals(STATUS_AUTH_FAILED_FROM_APP)){
				channelSatusListener.scFailed("Authentication failer");
			}else if (SW.equals(STATUS_AUTH_FAILED_FROM_SE)){
				channelSatusListener.scFailed("Authentication failer");
			}else if (SW.equals(STATUS_PASSWORD_CHANGED)){
				channelSatusListener.scPasswordChanged();
			}else if (SW.equals(STATUS_PASSWORD_CHANGE_FAILED)){
				channelSatusListener.scFailed("Failed to change password");
			}else if (SW.equals(STATUS_PASSWORD_SHORT)){
				channelSatusListener.scFailed("password too short");
			}else  {
				channelSatusListener.scFailed(SW);
			}
		}
	};

 
	/**
 	 * Constructs a ISO/IEC 7816-4 Secure Messaging Command APDU (ETSI TS 102 176-2 format) for commandAPDU 
	 * and returns a decoded response data
	 * 
	 * <p> This method handles all Secure Messaging related processing on the Command APDU and Response APDU.
	 * If the verification of the incoming ResponseAPDU fails, it returns the status word of the response 
	 * 
	 * @param commandApdu a CommandAPDU to be encoded
	 * @return decoded response data if the response is verified, otherwise status word of the response
	 */
	public byte[] encodeAndSend(CommandApdu commandApdu) {

		if (sessionSecure) {

			byte[] wrappedApdu = usmileSecureMessaging.wrap_request_APDU(commandApdu); 		 
			byte[] responseBuffer = seConnection.sendCommand(wrappedApdu);
			respApdu = new ResponseApdu(responseBuffer);
			if (respApdu.statusOk()) {
				SW = Converter.getHex(respApdu.getSW());
				if(responseBuffer.length > 2){
					return usmileSecureMessaging.unwrap_response_APDU(respApdu); 
				}else{
					return responseBuffer;
				}
				
			}else{
				return respApdu.getSW();
			}

		}else{
			try {
				throw( new Exception("Secure Session not established "));
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return null;
		}

	} 
	
	@Override
	public void seServiceAvailable(String[] terminals) {
		// TODO Auto-generated method stub
		channelSatusListener.serviceAvailable(terminals);
	}
	 
 

}
