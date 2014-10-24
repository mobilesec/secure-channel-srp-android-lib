package at.fhooe.usmile.securechannel;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * @author Endalkachew Asnake
 * 
 */
class SecureMessaging {

	private static final int LENGTH_SUBKEY = 16;
	private static final int BLOCK_SIZE = 16;
	private static final int LENGH_CHECK_SUM = 8;

	private byte[] mSeedKey;
	private byte[] mEncryptionKey;
	private byte[] mMacKey;
	private byte[] mMacSubkey_1;
	private byte[] mMacSubKey_2;

	private short sendSequenceCounter;
	private MessageDigest msgDigest_SHA256;
	private Cipher mAESCipher;

	private IvParameterSpec ivSpec;
	private IvParameterSpec macIVSpec;
	private SecretKeySpec mKey;
	private SecretKeySpec mMacSecKeySpec1;
	private SecretKeySpec mMacSecKeySpec2;

	/**
	 * Constructor, Initializes secure messaging with seedKey and iv
	 * 
	 * @param seedKey a cryptographic key from the secure channel key agreement
	 * @param iv initialization vector from the secure channel key agreement
	 */
	public SecureMessaging(byte[] seedKey, byte[] iv) {
		mSeedKey = seedKey;
		ivSpec = new IvParameterSpec(iv);
		macIVSpec = new IvParameterSpec(new byte[16]);
		// TODO send sequence counter should be changed to 8 byte number from
		// random parameters exchanged during key agreement
		sendSequenceCounter = 0x0000;
		try {
			msgDigest_SHA256 = MessageDigest.getInstance("SHA-256");
			mAESCipher = Cipher.getInstance("AES/CBC/NoPadding");
			deriveSessionKeys();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	/**
	 * derives MAC and Encryption session Key according to ANSI X9.63
	 */
	private void deriveSessionKeys() {

		msgDigest_SHA256.reset();
		byte[] hash1Input = concatArray(mSeedKey, new byte[] { 1 });
		byte[] hash2Input = concatArray(mSeedKey, new byte[] { 2 });

		mEncryptionKey = msgDigest_SHA256.digest(hash1Input);
		mMacKey = msgDigest_SHA256.digest(hash2Input);

		mMacSubkey_1 = Arrays.copyOf(mMacKey, LENGTH_SUBKEY);
		mMacSubKey_2 = Arrays.copyOfRange(mMacKey, LENGTH_SUBKEY, LENGTH_SUBKEY
				+ LENGTH_SUBKEY);
		mMacSecKeySpec1 = new SecretKeySpec(mMacSubkey_1, "AES");
		mMacSecKeySpec2 = new SecretKeySpec(mMacSubKey_2, "AES");

	}

	/**
	 * Constructs a ISO/IEC 7816-4 Secure Messaging Command APDU (ETSI TS 102 176-2 format)
	 * 
	 * @param commandAPDU CommandApdu Object to be encoded
	 * @return secure messaging CommandAPDU buffer
	 */
	public byte[] wrap_request_APDU(CommandApdu commandAPDU) {
		if (sendSequenceCounter == (short) 0xffff) {
			// exception ... re initialize key agreement or reset counter
			return null;
		}

		/**
		 * get data section of apdu and pad
		 */
		byte[] unpadedData = commandAPDU.getData();
		byte[] paddedData = get_ISO7816_Padded(unpadedData);

		/**
		 * drive session keys
		 */

		byte[] encryptedData = encryptAES(paddedData, mEncryptionKey, 0,
				paddedData.length);

		/**
		 * form D0 87
		 */
		byte[] DO87_header = new byte[] { (byte) 0x87,
				(byte) (encryptedData.length + 1), (byte) 0x01 };
		byte[] DO87 = concatArray(DO87_header, encryptedData);

		/**
		 * form DO97
		 */
		byte[] DO97 = new byte[] { (byte) 0x97, (byte) 0x01,
				commandAPDU.getLE() };

		/**
		 * pad apdu header
		 */
		byte[] apduHeader = commandAPDU.getHeader();
		byte[] paddedHeader = get_ISO7816_Padded(apduHeader);

		/**
		 * concatenate padded header + DO87 + padded D097 and compute checksum
		 */
		byte[] checksumInput = concatArray(paddedHeader, DO87);
		checksumInput = concatArray(checksumInput, DO97);
		checksumInput = get_ISO7816_Padded(checksumInput);

		byte[] checksum = getChecksum_AES_CMAC_Version(checksumInput);

		/**
		 * form DO 8E
		 */
		byte[] DO8E = new byte[LENGH_CHECK_SUM + 3];
		DO8E[0] = (byte) 0x87;
		DO8E[1] = LENGH_CHECK_SUM;
		System.arraycopy(checksum, 0, DO8E, 2, LENGH_CHECK_SUM);

		// New LE set to 0 for the moment
		DO8E[LENGH_CHECK_SUM + 2] = (byte) 0x00;

		/**
		 * form protected apdu ( Cmd Hearder + new LC + DO87 + D097 + DO8E
		 */
		int newLC = DO87.length + DO97.length + DO8E.length;
		if (newLC > 255) {
			// Exception apdu to long
			return null;
		}
		byte[] protectedApdu = concatArray(apduHeader,
				new byte[] { (byte) newLC });

		protectedApdu = concatArray(protectedApdu, DO87);
		protectedApdu = concatArray(protectedApdu, DO97);
		protectedApdu = concatArray(protectedApdu, DO8E);

		return protectedApdu;
	}

	
	/**
	 * Processes ISO/IEC 7816-4 Secure messaging ResponseAPDU (ETSI TS 102 176-2 format) 
	 * returns response data contained
	 *  
	 * @param respApdu secure messaging Response APDU object
	 * @return response data if the processing is successful or null if respAPDU is malformed
	 */
	public byte[] unwrap_response_APDU(ResponseApdu respApdu) {
		byte[] protectedResponse = respApdu.getData();
		// check if it is protected
		assert (protectedResponse[0] == (byte) 0x87);

		int DO87Len = ((byte)(protectedResponse[1]) & 0xff) + 2;
		byte[] DO87 = Arrays.copyOf(protectedResponse, DO87Len);

		int offsetDO99 = DO87Len;
		int offsetDO8E = offsetDO99 + 4;
		byte[] DO99 = Arrays.copyOfRange(protectedResponse, offsetDO99,
				offsetDO8E);

		byte[] DO8E = Arrays.copyOfRange(protectedResponse, offsetDO8E,
				offsetDO8E + LENGH_CHECK_SUM + 2);

		/**
		 * compute check sum from DO87 + DO99
		 */

		byte[] checksumInput = concatArray(DO87, DO99);
		checksumInput = get_ISO7816_Padded(checksumInput);

		byte[] checksum = getChecksum_AES_CMAC_Version(checksumInput);

		/**
		 * extract incoming checksum from DO8E and compare
		 */

		byte[] incomingChecksum = Arrays.copyOfRange(DO8E, 2,
				LENGH_CHECK_SUM + 2);
		if (Arrays.equals(checksum, incomingChecksum)) {
			/**
			 * get encyrpted data from DO87 and decrypt
			 */
			int encryptedDataLen = (DO87[1] & 0xff) -1;
			byte[] encryptedData = Arrays.copyOfRange(DO87, 3,
					encryptedDataLen + 3);
			byte[] unprotectedRespPadded = decryptAES(encryptedData,
					mEncryptionKey, 0, encryptedDataLen);
			byte[] unprotectedResponse = get_ISO7816_Unpadded(unprotectedRespPadded);

			return unprotectedResponse;

		} else {
			// exception checksum error
			return null;
		}
	}

	/**
	 * Calculates MAC over input according to ETSI TS 102 176-2 - 
	 * Which uses CBC MAC with Encryption of Last Block
	 * 
	 * @param input
	 * @return
	 */
	public byte[] getChecksum_AES_CBC_MAC_Version(byte[] input) {
		if (input.length % BLOCK_SIZE != 0) {
			// exception incorrect input block size
			return null;
		}
		sendSequenceCounter += 1;

		byte[] paddedSendSequenceCounter = new byte[BLOCK_SIZE];
		byte[] sSC = new byte[] { (byte) ((sendSequenceCounter & 0xff00) >> 8),
				(byte) (sendSequenceCounter & 0x00ff) };
		System.arraycopy(sSC, 0, paddedSendSequenceCounter, BLOCK_SIZE
				- sSC.length, sSC.length);
		/**
		 * start encryption with padded sequenceCounter
		 */
		try {
			mAESCipher.init(Cipher.ENCRYPT_MODE, mMacSecKeySpec1, macIVSpec);
			mAESCipher.update(paddedSendSequenceCounter);
			byte[] cipherOut =	mAESCipher.doFinal(input);
			byte[] cbcMac = Arrays.copyOfRange(cipherOut, cipherOut.length - BLOCK_SIZE, cipherOut.length);
			// encrypt last block
			mAESCipher.init(Cipher.ENCRYPT_MODE, mMacSecKeySpec2, macIVSpec);
			cbcMac = mAESCipher.doFinal(cbcMac) ;
			return Arrays.copyOfRange(cbcMac, 0, LENGH_CHECK_SUM);
			
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Calculates MAC over input according to RFC 4493 - The last block to this input is always padded 
	 * as specified in ETSI TS 102 176-2. There for The second Mac sub key is XORed with the last block 
	 * before encryption
	 * 
	 * @param input
	 * @return
	 */
	public byte[] getChecksum_AES_CMAC_Version(byte[] input) {
		if (input.length % BLOCK_SIZE != 0) {
			// exception incorrect input block size
			return null;
		}
		sendSequenceCounter += 1;

		byte[] paddedSendSequenceCounter = new byte[BLOCK_SIZE];
		byte[] sSC = new byte[] { (byte) ((sendSequenceCounter & 0xff00) >> 8),
				(byte) (sendSequenceCounter & 0x00ff) };
		System.arraycopy(sSC, 0, paddedSendSequenceCounter, BLOCK_SIZE
				- sSC.length, sSC.length);
		/**
		 * start encryption with padded sequenceCounter
		 */
	 
		
		try {
			mAESCipher.init(Cipher.ENCRYPT_MODE, mMacSecKeySpec1, macIVSpec);
			mAESCipher.update(paddedSendSequenceCounter);
			
			//int len = input.length / BLOCK_SIZE;
			byte[] lastBlock = Arrays.copyOfRange(input, input.length - BLOCK_SIZE, input.length);
			int j = 0;
			for (byte b : lastBlock) {
				lastBlock[j] = (byte) (mMacSubKey_2[j] ^ b);
				j++;
			}
			mAESCipher.update(input, 0, input.length - BLOCK_SIZE);
			byte[]  cmac = mAESCipher.doFinal(lastBlock);
			
			return Arrays.copyOfRange(cmac, 0, LENGH_CHECK_SUM);
			
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
 	
	}
	/**
	 * Performs AES-CBC-256 encryption with the specified parameters
	 * 
	 * @param buffer a byte array Buffer containing the data to be encrypted
	 * @param key encryption key
	 * @param offset the offset of the data in the buffer 
	 * @param length length of the data
	 * @return encrypted byte array buffer if encryption is successful, null otherwise
	 */
	private byte[] encryptAES(byte[] buffer, byte[] key, int offset, int length) {
		try {
			mKey = new SecretKeySpec(key, "AES");
			mAESCipher.init(Cipher.ENCRYPT_MODE, mKey, ivSpec);

			return mAESCipher.doFinal(buffer, offset, length);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 *Performs AES-CBC-256 decryption with the specified parameters
	 *
	 * @param buffer buffer containing the cipher
	 * @param key encryption key
	 * @param offset the offset of the cipher in the buffer 
	 * @param length length of the cipher
	 * @return decrypted byte array buffer if decryption is successful, null otherwise
	 */
	private byte[] decryptAES(byte[] buffer, byte[] key, int offset, int length) {

		try {

			mKey = new SecretKeySpec(key, "AES");
			mAESCipher.init(Cipher.DECRYPT_MODE, mKey, ivSpec);
			return mAESCipher.doFinal(buffer, offset, length);

		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * performs padding of the input according to ISO/IEC 7816
	 * 
	 * @param unpadded input to be padded
	 * @return ISO/IEC 7816 padded output
	 */
	public byte[] get_ISO7816_Padded(byte[] unpadded) {

		int length = unpadded.length;
		byte padLength = (byte) (0x10 - (length % 0x10));
		byte[] padded = Arrays.copyOf(unpadded, length + padLength);
		padded[length] = (byte) 0x80;
		return padded; 
	}

	/**
	 * removes padding from ISO/IEC 7816-4 padded byte array buffer
	 *  
	 * @param padded padded input
	 * @return unpadded byte array buffer
	 */
	public byte[] get_ISO7816_Unpadded(byte[] padded) {

		int length = padded.length;
		int unpaddedLen = -1;
		for (int i = length - 1; i >= 0; i--) {
			if (padded[i] == (byte) 0x80) {
				unpaddedLen = i;
				break;
			}
		}
		if (unpaddedLen > -1) {
			return Arrays.copyOf(padded, unpaddedLen);
		} else {
			// padding exception
			return null;
		}
	}

	/**
	 * Concatenates two byte arrays in the given order
	 * 
	 * @param first the first array
	 * @param second the second array
	 * @return concatenated array
	 */
	public static byte[] concatArray(byte[] first, byte[] second) {
		byte[] result = new byte[first.length + second.length];
		System.arraycopy(first, 0, result, 0, first.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}

	
	/**
	 * Applet side processing for Test purpose: decodes  Secure messaging Command APDU
	 * 
	 * @param apduBuffer
	 * @return
	 */
	public byte[] unwrap_request_APDU(byte[] apduBuffer) {
		byte[] data = Arrays.copyOfRange(apduBuffer, CommandApdu.OFFSET_DATA,
				apduBuffer.length);
		// get DO 87
		assert (data[0] == (byte) 0x87);
		int encDatalen = data[1] - 1;
		int offsetDO97 = encDatalen + 3;
		int offsetDO8E = offsetDO97 + 3;

		byte[] DO87 = new byte[encDatalen + 3];
		byte[] DO97 = new byte[3];
		byte[] checksum = new byte[LENGH_CHECK_SUM];

		System.arraycopy(data, 0, DO87, 0, DO87.length);
		System.arraycopy(data, offsetDO97, DO97, 0, 3);
		System.arraycopy(data, offsetDO8E + 2, checksum, 0, LENGH_CHECK_SUM);

		byte[] header = Arrays.copyOf(apduBuffer, 4);
		byte[] paddedHeader = get_ISO7816_Padded(header);

		// compute check sum
		byte[] checksumInput = concatArray(paddedHeader, DO87);
		checksumInput = concatArray(checksumInput, DO97);
		checksumInput = get_ISO7816_Padded(checksumInput);

		byte[] computedChecksum = getChecksum_AES_CBC_MAC_Version(checksumInput);

		if (Arrays.equals(computedChecksum, checksum)) {
 			byte[] encryptedApdu = Arrays.copyOfRange(DO87, 3, encDatalen + 3);
			byte[] decryptedApdu = decryptAES(encryptedApdu, mEncryptionKey, 0,
					encryptedApdu.length);
			return get_ISO7816_Unpadded(decryptedApdu);
		}
		return null;
	}

	/** 
	 * Applet side processing for Test purpose: creates  Secure messaging Response APDU 
	 * 
	 * @param response
	 * @return
	 */
	public byte[] create_response_APDU(byte[] response) {

		byte[] paddedResponse = get_ISO7816_Padded(response);
		byte[] encryptedResp = encryptAES(paddedResponse, mEncryptionKey, 0,
				paddedResponse.length);
		byte[] SW = new byte[] { (byte) 0x90, 0x00 };

		int respLen = encryptedResp.length;

		byte[] DO87 = concatArray(new byte[] { (byte) 0x87,
				(byte) (respLen + 1), (byte) 0x01 }, encryptedResp);

		byte[] DO99 = new byte[] { (byte) 0x99, (byte) 0x02, SW[0], SW[1] };

		byte[] checksumInput = concatArray(DO87, DO99);
		checksumInput = get_ISO7816_Padded(checksumInput);
		byte[] checksum = getChecksum_AES_CBC_MAC_Version(checksumInput);

		byte[] DO8E = new byte[LENGH_CHECK_SUM + 2];
		DO8E[0] = (byte) 0x8E;
		DO8E[1] = (byte) LENGH_CHECK_SUM;
		System.arraycopy(checksum, 0, DO8E, 2, LENGH_CHECK_SUM);

		byte[] protectedApdu = concatArray(DO87, DO99);
		protectedApdu = concatArray(protectedApdu, DO8E);
		protectedApdu = concatArray(protectedApdu, SW);

		return protectedApdu;

	}

}
