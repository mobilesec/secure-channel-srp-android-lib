package at.fhooe.usmile.securechannel;

import java.security.Security;
import java.util.Arrays;

import android.content.Context;
import android.os.Handler;
import android.util.Log;
import at.fhooe.usmile.securechannel.keyagreement.ECSRP;
import at.fhooe.usmile.securechannel.keyagreement.UsmileKeyAgreement;

public class UsmileSecureChannel_EC192 implements ISEServiceStatusListener{

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private static final int LENGTH_EC_POINT =  ECSRP.LENGTH_EC_POINT;
	private static final int LENGTH_SALT = 16;
	private static final int LENGTH_IV = 16;
	
    private final static byte INS_KEYAG_STAGE1 = 0x01;
    private final static byte INS_KEYAG_STAGE3 = 0x03;

    private final static byte INS_SECURE_MSG = 0x30;
    private final static byte CLA = (byte) 0x80;
    private final static byte P1 = 0x00;
    private final static byte P2 = 0x00;
    private final static byte LE = 0x00;
    private final static String STATUS_CONNECTED = "9000";
    private final static String STATUS_BLOCKED = "0100";
    private final static String STATUS_TERMINATED = "0f00";

	private final static String STATUS_INITIALIZED = "1000";
	private final static String STATUS_SELECTION_FAILED = "0110";
	private final static String STATUS_AUTH_FAILED_FROM_SE = "0120";
	private final static String STATUS_AUTH_FAILED_FROM_APP = "0130";
	private final static String STATUS_PASSWORD_CHANGED = "0104";
	private final static String STATUS_PASSWORD_CHANGE_FAILED = "0105";
	private final static String STATUS_PASSWORD_SHORT = "0106";
	
    static private UsmileKeyAgreement usmileKeyAgreement;
    
    static private SecureMessaging usmileSecureSession;
    private boolean sessionSecure;
    
	Handler handler = new Handler();

	byte[] incomingPublicParam;
	private byte[] salt;
	private byte[] iv;
    private byte[] AID;
    
    	private int selectedReader;
	Thread keyAgThread;
	Thread initThread;
	Thread authThread;

	CommandApdu cmdApdu;
    private CommandApdu cmdApdu1;
    
    private String SW;

	SEConnection seConnection;
	//ChannelStatusListener channelSatusListener;
	IChannelStatusListener channelSatusListener;
	
    //////////////////////////** for performance measurement */////////////////////////////
    long starttime = 0L;
    long endtime = 0L;
    long step1SEresponseTime = 0L;
    long step2SEresponseTime = 0L;
    long overAllKeyAgreementElapsedTime = 0L;

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

	public long getOverallTime(){
		return overAllKeyAgreementElapsedTime;
	}
	
    ////////////////////////////////////////////////////////////////////

    public UsmileSecureChannel_EC192(Context context,
			IChannelStatusListener listener) {

		seConnection = new SEConnection(context, this);
		usmileKeyAgreement = new ECSRP(); 
		channelSatusListener = listener;
    }

    public boolean isSessionSecure() {
        return sessionSecure;
    }

	/**
	 * Closes the secure channel 
	 */
	public void closeSession() {
		sessionSecure = false;
		seConnection.closeConnection();
	}


	public void initConnection(byte[] appletID, int readerIndex){
		
		AID = appletID;
		selectedReader = readerIndex;
		
		initThread = new Thread() {
			public void run() {
				
				System.out.println("AID "+ Converter.getHex(AID));
				if(seConnection.selectApplet(AID, selectedReader)){
					starttime = System.nanoTime();

	                SW = runKeyAgreement();
				}else{
					SW = STATUS_SELECTION_FAILED;
				}

				handler.post(submitToCallBackListener);
			}
		};
		initThread.start();
	}

	public void authenticate(final byte[] userID, final byte[] password){
		authThread = new Thread() {

			public void run() {
				ResponseApdu respApdu;
				
				SW = STATUS_AUTH_FAILED_FROM_SE;

				byte[] authData = usmileKeyAgreement.computeSessionKey(
						incomingPublicParam, userID, salt,
						password);

    			cmdApdu1 = getCommandApdu(CLA, INS_KEYAG_STAGE3, P1, P2, authData,
    					LE);

    			respApdu = new ResponseApdu(seConnection.sendCommand(cmdApdu1
    					.getApduBuffer()));

    			step2SEresponseTime = seConnection.getElapsedTime() / 1000;

    			System.out.println("Authdata "+Converter.getHex(authData));
    			System.out.println("Rspone "+Converter.getHex(respApdu.getApduBuffer()));
    			if (statusOk(respApdu)) {
    				if (usmileKeyAgreement.verifySEResponse(respApdu.getData())) {
    					endtime = System.nanoTime();
    					
    					sessionSecure = true;
    					usmileSecureSession = new SecureMessaging(
    							usmileKeyAgreement.getSessionKey(), iv);

    					overAllKeyAgreementElapsedTime = (endtime - starttime) / 1000;
    					
    					System.out.println("success in "
    							+ overAllKeyAgreementElapsedTime + " µsec");
    					System.out.println("Authenticated \n");
    					
    					SW = STATUS_CONNECTED;
    				} else {
    					SW = STATUS_AUTH_FAILED_FROM_APP;
    				}
    			} else {
    				Log.i("uschannel ", "Device-side verification failed ");
    				SW = STATUS_AUTH_FAILED_FROM_SE;
    			}
                
				handler.post(submitToCallBackListener);
			}
		};
		authThread.start();
		
	}
    /**
     * establishes a secure connection to the applet implementing the
     * corresponding secure channel protocol using passwordByes
     *
     * the calling class is notified when process is complete via implented
     * interfaces
     *
     * @param passwordBytes
     */
    public void establishSecureSession(final byte[] passwordBytes) {

        /**
         * compute SHA-256 of password bytes
         */
        // **********************   put here code to compute passwordBytes SHA 256 digest
        keyAgThread = new Thread() {
            public void run() {

            }
        };
        keyAgThread.start();
    }

    public CommandApdu getCommandApdu(byte CLA, byte INS, byte P1, byte P2, byte[] data, byte Le) {
    	CommandApdu cApdu = new CommandApdu(CLA, INS, P1, P2, data, Le);
        return cApdu;
    }

    /**
     * executes complete key agreement process
     *
     * @param passwordBytes
     * @return 
     */
    private String runKeyAgreement() {
    	String status = STATUS_TERMINATED;
    	
        starttime = System.nanoTime();
        
        byte[] publicThis = usmileKeyAgreement.init();
        System.out.println("client initialization " + (System.nanoTime()-starttime)/1000);
        
        /**
         * send 255 as data and last byte as LE
         */
        cmdApdu1 = getCommandApdu(CLA, INS_KEYAG_STAGE1, P1, P2,
                publicThis, LE);

        ResponseApdu respApdu = new ResponseApdu(seConnection.sendCommand(cmdApdu1.getApduBuffer()));
		step1SEresponseTime = seConnection.getElapsedTime() / 1000;
		
        byte[] serverInitSRPResponse = respApdu.getData();
        
        /**
         * for performance testing *
         */
        if (statusOk(respApdu)) 
        {
            long startClient = System.nanoTime();
			incomingPublicParam = Arrays.copyOfRange(serverInitSRPResponse,
					0, LENGTH_EC_POINT);
			salt = Arrays.copyOfRange(serverInitSRPResponse,
					LENGTH_EC_POINT, LENGTH_EC_POINT + LENGTH_SALT);
			iv = Arrays.copyOfRange(serverInitSRPResponse,
					LENGTH_EC_POINT + LENGTH_SALT, LENGTH_EC_POINT
							+ LENGTH_SALT + LENGTH_IV);

			System.out.println("Client public param " + Converter.getHex(incomingPublicParam));
            long endClient = System.nanoTime();
            
            System.out.println("client secret computation " + (endClient-startClient)/1000);
            
			status = STATUS_INITIALIZED;
        } else {
            System.out.println("failed : ");
            status = STATUS_AUTH_FAILED_FROM_SE;		
        }
        
        return status;
    }

    /**
     * Once secure session is established this method is used to encode and send
     * request APDU to the applet
     *
     * handles all processing ... wrapping and unwrapping of request and
     * Response and returns back plain response APDU
     *
     * @param cmdApdu
     * @return
     */
    public byte[] encodeAndSend(byte[] cmdApduBuffer) {

        if (sessionSecure) {
            
           CommandApdu capdu = new CommandApdu(cmdApduBuffer[0], cmdApduBuffer[1],  cmdApduBuffer[2],  cmdApduBuffer[3], Arrays.copyOfRange(cmdApduBuffer, 5, (int)(cmdApduBuffer[4]&0xff) + 5),
                    LE);
            byte[] wrapedBuffer = usmileSecureSession.wrap_request_APDU(capdu);
            cmdApdu1 = getCommandApdu(wrapedBuffer[0], wrapedBuffer[1],  wrapedBuffer[2],  wrapedBuffer[3], Arrays.copyOfRange(wrapedBuffer, 5, (int)(wrapedBuffer[4]&0xff) + 5),
                    LE);

            ResponseApdu respApdu;
            respApdu = new ResponseApdu(seConnection.sendCommand(cmdApdu1.getApduBuffer()));
            if (statusOk(respApdu)) {
                return usmileSecureSession.unwrap_response_APDU(respApdu);
            } else {
                return respApdu.getSW();
            }

        } else {
            try {
                throw (new Exception("Secure Session not established "));
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

    }

    public boolean statusOk(ResponseApdu resp) {
    	return resp.statusOk();
    }

	@Override
	public void seServiceAvailable(String[] terminals) {
		// TODO Auto-generated method stub
		channelSatusListener.serviceAvailable(terminals);
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
				channelSatusListener.scFailed("Authentication failure from App");
			}else if (SW.equals(STATUS_AUTH_FAILED_FROM_SE)){
				channelSatusListener.scFailed("Authentication failure from SE");
			}else if (SW.equals(STATUS_PASSWORD_CHANGED)){
				channelSatusListener.scPasswordChanged();
			}else if (SW.equals(STATUS_PASSWORD_CHANGE_FAILED)){
				channelSatusListener.scFailed("Failed to change password");
			}else if (SW.equals(STATUS_PASSWORD_SHORT)){
				channelSatusListener.scFailed("Password too short");
			}else  {
				channelSatusListener.scFailed(SW);
			}
		}
	};
 
}
