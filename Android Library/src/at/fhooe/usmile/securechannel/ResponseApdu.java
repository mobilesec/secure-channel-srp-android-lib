package at.fhooe.usmile.securechannel;

import java.util.Arrays;

 /**
 * @author Endalkachew Asnake
 *
 */
class ResponseApdu {

	byte[] mApduBuffer;
	byte[] mData;
	byte[] mSW;
	
	static final byte[] swOk = new byte[]{(byte)0x90, (byte)0x00};
	
	/**
	 * returns the response APDU 
	 * 
	 * @return
	 */
	public byte[] getApduBuffer(){
		return mApduBuffer;
	}
	/**
	 * return the response data of the Response APDU
	 * 
	 * @return
	 */
	public byte[] getData(){
		return mData;
	}
	
	/**
	 * returns the status word of the Response APDU
	 * 
	 * @return SW1,SW2
	 */
	public byte[] getSW(){
		return mSW;
	}
	
	/**
	 * @param args
	 */ 
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

	/**
	 * Constructor
	 * 
	 * constructs ISO/IEC 7816-4 Response APDU object from byte array
	 * 
	 * @param apdu
	 */
	public ResponseApdu(byte[] apdu){
		mApduBuffer = apdu; 
		mData = Arrays.copyOf(mApduBuffer, mApduBuffer.length - 2);
		mSW = Arrays.copyOfRange(mApduBuffer, mApduBuffer.length - 2, mApduBuffer.length);
	}
	
	/**
	 * checks if the status of this Response APDU object
	 * 
	 * @return true if the status word is '9000', false otherwise
	 */
	public boolean statusOk() {

		if (Arrays.equals(mSW, swOk)) {
			return true;
		}
		return false;
	}
	 
}
