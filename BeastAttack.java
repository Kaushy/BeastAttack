import java.io.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.util.Date;


public class BeastAttack
{
	public static void main(String[] args) throws Exception
        {
		byte[] ciphertext=new byte[1024]; // will be plenty big enough
		byte[] newCipherText=new byte[1024]; 
        	byte[] prefix = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0x00, (byte)0x00};
		byte[] dummyArray = new byte[8];
		byte[] tempArray = new byte[8];
		byte[] previousIV = new byte[8];
		byte[] newlyPreditedIV = new byte[8];
		byte[] XORPredictedIVWithPrefix = new byte[8];
		
		byte guessedCharacterReturned = 0;
		int blockDecoded = 6;
	
		
			int length=callEncrypt(prefix,7,ciphertext);
			long previousDate = new Date().getTime();
			byte[] currentIV = Arrays.copyOfRange(ciphertext, 0, 8);
			byte[] encBlock = Arrays.copyOfRange(ciphertext, 8, 16);
			previousIV = Arrays.copyOfRange(ciphertext, 0, 8);	    
        		System.out.println("Original Ciphertext"+length);
			for(int i=0; i<length; i++)
			{
	   			if (i%8 == 0)
	    				System.out.println();
				System.out.print(String.format("%02x ",ciphertext[i]));
	    		}
			findoutHowtodothis(encBlock,newCipherText,previousIV,newlyPreditedIV,previousDate,currentIV);
			
	 }

/*************************************************************************************************************************************************/
	public static void findoutHowtodothis(byte[]encBlock, byte[]currentCipherText,byte[]previousIV,byte[]newlyPreditedIV,long previousDate,byte[]currentIV) throws IOException
	{
		int guessIndex = 0;
		byte guessChar = -127; 
		
		while (true){
			byte[] guessIV = guessIV(currentIV, previousDate);
			// calcucate next
			byte[] padding = new byte[8];
			padding[7] = guessChar;
			for (int i = 0; i < 8; i++) {
				padding[i] = (byte) (guessIV[i] ^ previousIV[i] ^ padding[i]);
			}

			previousDate = new Date().getTime();
			callEncrypt(padding, 8, currentCipherText);
			currentIV = getBlock(currentCipherText, 0, 8);

			// Check Correct guess
			if (Arrays.equals(currentIV, guessIV)) {

				System.out.println("Trying " + (char) guessChar);

				if (Arrays.equals(encBlock, getBlock(currentCipherText, 1, 8))) {
					System.out.println("Letter guessed");
					break;
				}
				guessChar = (byte) (guessChar + 1);
				if (guessChar == -128) {
					System.out.println("Cannot guess");
					System.exit(0);
				}
				// System.exit(0);
			}
		}
	}
/*************************************************************************************************************************************************/
   	public static void dummyProgramPrintingAllCode256Times(byte[] ciphertext,byte[]newCipherText,byte[]prefix,byte[]previousIV,byte[]newlyPreditedIV, byte[]XORPredictedIVWithPrefix)
	{
		// e.g. this prints out the result of an encryption with no prefix
		try {
       			int length=callEncrypt(prefix,8,ciphertext);   
		
			System.out.println("Original Ciphertext "+length);
        		for(int i=0; i<length; i++)
        		{
            			if (i%8 == 0)
                    			//System.out.println();
            			if (i<8){
                			previousIV[i] = ciphertext[i];
                			newlyPreditedIV[i] = previousIV[i];
           	 	 	}
            			System.out.print(String.format("%02x ", ciphertext[i]));
        		}

        		for (int j=-128; j<128; j++)
        		{
               			Byte b = Byte.valueOf(j+"");
                		newlyPreditedIV[7] = b;
                		//System.out.println(String.format("Printing newlyPredicted IV  %02x ", newlyPreditedIV[7]));
                		int predictedIVIntegerValue = 0;
                		int previousIVIntegerValue = 0;
                		int prefixIntegerValue = 0;
                		int xor = 0;
                		for (int k=0; k<8; k++){
                        		predictedIVIntegerValue = (int)newlyPreditedIV[k];
                        		previousIVIntegerValue = (int)previousIV[k];
                        		prefixIntegerValue = (int)prefix[k];
                        		xor = predictedIVIntegerValue^previousIVIntegerValue^prefixIntegerValue;
                        		byte c = (byte)(0xff & xor);
                        		XORPredictedIVWithPrefix[k] = c;
                		}
        			int lengthOfPredictedBlock=callEncrypt(XORPredictedIVWithPrefix,8,newCipherText);            
        			System.out.println("\nSecond Ciphertext "+lengthOfPredictedBlock);
        			for(int i=0; i<lengthOfPredictedBlock; i++)
        			{
            				if (i%8 == 0)
                    				//System.out.println();
            				System.out.print(String.format("%02x ", newCipherText[i]));
        			}
        		}
		}
		catch (Exception e){
		}
	}

	static byte[] guessIV(byte[] prevIV, long prevTime) {
		long lprevIV = ByteBuffer.wrap(prevIV).getLong();
		long diff = (new Date().getTime() - prevTime) * 5;
		return ByteBuffer.allocate(8).putLong(lprevIV + diff).array();
	}
	static byte[] getBlock(byte[] c, int block, int blockSize) {
		return Arrays.copyOfRange(c, blockSize * block, blockSize * block
				+ blockSize);
	}

	// a helper method to call the external programme "encrypt" in the current directory
    // the parameters are the plaintext, length of plaintext, and ciphertext; returns length of ciphertext
    static int callEncrypt(byte[] prefix, int prefix_len, byte[] ciphertext) throws IOException
    {
	HexBinaryAdapter adapter = new HexBinaryAdapter();
	Process process;
	
	// run the external process (don't bother to catch exceptions)
	if(prefix != null)
	{
	    // turn prefix byte array into hex string
	    byte[] p=Arrays.copyOfRange(prefix, 0, prefix_len);
	    String PString=adapter.marshal(p);
	    process = Runtime.getRuntime().exec("./encrypt "+PString);
	}
	else
	{
	    process = Runtime.getRuntime().exec("./encrypt");
	}

	// process the resulting hex string
	String CString = (new BufferedReader(new InputStreamReader(process.getInputStream()))).readLine();
	byte[] c=adapter.unmarshal(CString);
	System.arraycopy(c, 0, ciphertext, 0, c.length); 
	return(c.length);
    }
}
