package at.fhooe.usmile.securechannel;

/**
 * @author Endalkachew Asnake
 * 
 */
public class CommandApdu {

	static final int OFFSET_CLA = 0;
	static final int OFFSET_INS = 1;
	static final int OFFSET_P1 = 2;
	static final int OFFSET_P2 = 3;
	static final int OFFSET_LC = 4;
	static final int OFFSET_DATA = 5;

	byte mCLA;
	byte mINS;
	byte mP1;
	byte mP2;
	byte mLC;
	byte[] mData;
	byte mLE;

	byte[] apduBuffer;

	/**
	 * returns CLA byte of the Command APDU
	 * 
	 * @return CLA
	 */
	public byte getCLA() {
		return mCLA;
	}

	/**
	 * sets CLA byte of the Command APDU
	 * 
	 * @param CLA
	 */
	public void setCLA(byte CLA) {
		this.mCLA = CLA;
	}

	/**
	 * returns INS byte of the Command APDU
	 * 
	 * @return INS
	 */
	public byte getINS() {
		return mINS;
	}

	/**
	 * sets INS byte of the Command APDU
	 * 
	 * @param INS
	 */
	public void setINS(byte INS) {
		this.mINS = INS;
	}

	/**
	 *returns P1 byte of the Command APDU
	 * 
	 * @return P1
	 */
	public byte getmP1() {
		return mP1;
	}

	/**
	 * sets P1 byte of the Command APDU
	 * 
	 * @param mP1
	 */
	public void setP1(byte mP1) {
		this.mP1 = mP1;
	}

	/**
	 * returns P2 byte of the Command APDU
	 * 
	 * @return
	 */
	public byte getP2() {
		return mP2;
	}

	/**
	 * sets P2 byte of the Command APDU
	 * 
	 * @param mP2
	 */
	public void setP2(byte mP2) {
		this.mP2 = mP2;
	}

	/**
	 * gets LC byte of the Command APDU
	 *  
	 * @return LC
	 */
	public byte getLC() {
		return mLC;
	}

	/**
	 * sets LC byte of the Command APDU
	 * 
	 * @param mLC
	 */
	public void setLC(byte mLC) {
		this.mLC = mLC;
	}

	/**
	 * returns Data contained in the Command APDU
	 * 
	 * @return
	 */
	public byte[] getData() {
		return mData;
	}

	/**
	 *returns the data contained in the Command APDU
	 * @param mData
	 */
	public void setData(byte[] mData) {
		this.mData = mData;
	}

	/**
	 * gets LE byte of the Command APDU
	 * 
	 * @return LE
	 */
	public byte getLE() {
		return mLE;
	}

	/**
	 * sets LE byte of the command APDU
	 * 
	 * @param mLE
	 */
	public void setLE(byte mLE) {
		this.mLE = mLE;
	}

	/**
	 * 
	 * @return
	 */
	public byte[] getApduBuffer() {
		return apduBuffer;
	}

	/**
	 * returns the Header part of the Command APDU without LE
	 * 
	 * @return Command APDU header without LE
	 */
	public byte[] getHeader() {
		return new byte[] { mCLA, mINS, mP1, mP2 };
	}

	/**
	 * Constructor
	 * 
	 * Constructs ISO/IEC 7816-4 Command APDU with the specified header and body values
	 * 
	 * @param CLA
	 * @param INS
	 * @param P1 
	 * @param P2
	 * @param data
	 * @param LE
	 */
	public CommandApdu(byte CLA, byte INS, byte P1, byte P2, byte[] data,
			byte LE) {
		mCLA = CLA;
		mINS = INS;
		mP1 = P1;
		mP2 = P2;
		mLC = (byte) data.length;
		mData = data;
		mLE = LE;
		createApduBuffer();
	}

	/**
	 * serializes this Command APDU object to byte array
	 */
	private void createApduBuffer() {
		if (mLC == 0) {
			apduBuffer = new byte[5];
		} else {
			apduBuffer = new byte[mData.length + 6];
		}
		apduBuffer[0] = mCLA;
		apduBuffer[1] = mINS;
		apduBuffer[2] = mP1;
		apduBuffer[3] = mP2;
		if (mData.length > 0) {
			apduBuffer[4] = mLC;
			System.arraycopy(mData, 0, apduBuffer, 5, mData.length);
			apduBuffer[5 + mData.length] = mLE;
		} else {
			apduBuffer[4] = mLE;
		}
	}

	/**
	 * returns byte array representations an ISO/IEC 7816-4 Command APDU using the specified header and body parts
	 * @param CLA
	 * @param INS
	 * @param P1
	 * @param P2
	 * @param data
	 * @param Le
	 * @return
	 */
	public static byte[] getCommandApdu(byte CLA, byte INS, byte P1, byte P2,
			byte[] data, byte Le) {

		byte[] apduByte = null;
		if (data.length == 0) {
			apduByte = new byte[5];
		} else {
			apduByte = new byte[data.length + 6];
		}
		apduByte[0] = CLA;
		apduByte[1] = INS;
		apduByte[2] = P1;
		apduByte[3] = P2;
		if (data.length > 0) {
			apduByte[4] = (byte) data.length;
			System.arraycopy(data, 0, apduByte, 5, data.length);
			apduByte[5 + data.length] = Le;
		} else {
			apduByte[4] = Le;
		}

		return apduByte;
	}

}
