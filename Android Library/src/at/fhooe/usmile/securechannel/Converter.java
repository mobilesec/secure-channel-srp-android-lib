package at.fhooe.usmile.securechannel;

/**
 * @author Endalkachew Asnake
 * 
 */
public class Converter {
	static final String HEXES = "0123456789ABCDEF";

	/**
	 * Converts byte array to Hex string
	 * 
	 * @param rawBytes byte array value
	 * @return Hex string representation of rawBytes
	 */
	public static String getHex(byte[] rawBytes) {
		if (rawBytes == null) {
			return null;
		}
		final StringBuilder hex = new StringBuilder(2 * rawBytes.length);
		for (final byte b : rawBytes) {
			hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(
					HEXES.charAt((b & 0x0F)));
		}
		return hex.toString();
	}

	/**
	 * Converts a Hex string to byte array
	 * 
	 * @param str the Hex string representation
	 * @return byte array representation of str
	 */
	public static byte[] hexStringToByteArray(String str) {
		int len = str.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character
					.digit(str.charAt(i + 1), 16));
		}
		return data;
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

}
