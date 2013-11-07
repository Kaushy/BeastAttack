import java.io.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.util.Arrays;

public class BeastAttack
{
	public static void main(String[] args) throws Exception
        {
		byte[] ciphertext=new byte[1024]; // will be plenty big enough
		byte[] newCipherText=new byte[1024]; 
        	byte[] prefix = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x41};
		byte[] previousIV = new byte[8];
		byte[] newlyPreditedIV = new byte[8];
		byte[] XORPredictedIVWithPrefix = new byte[8];
		int lastByte = 0;
		int oneBeforeLastByte = 0; 

		//dummyProgramPrintingAllCode256Times(ciphertext,newCipherText,prefix,previousIV,newlyPreditedIV,XORPredictedIVWithPrefix);
	
		// e.g. this prints out the result of an encryption with no prefix
		int length=callEncrypt(prefix,8,ciphertext);	    
        	System.out.println("Original Ciphertext"+length);
		for(int i=0; i<length; i++)
		{
	   		if (i%8 == 0)
	    			System.out.println();
	    		if (i<8){
				previousIV[i] = ciphertext[i];
				newlyPreditedIV[i] = previousIV[i];
				if (i==7){
				lastByte = (((previousIV[7] & 0xFF) + 100) < 256 ? ((previousIV[7] & 0xFF) + 100) : (previousIV[7] & 0xFF) - 156 );
				}
				if (i==6)
				oneBeforeLastByte = previousIV[6] & 0xFF;
	    		}
	    		//int t = (int)previousIV[7];
	    		System.out.print(String.format("%02x ",ciphertext[i]));
	    		//System.out.print(String.format(" Previous %02x ",previousIV[7]));
 	   		//System.out.print(String.format(" decimal "+ (previousIV[7] & 0xFF)));
	   		//System.out.print(String.format(" decimal signed "+ ((int)previousIV[7])));
	   	 	//System.out.println(String.format(" byte decimal signed %02x ",(byte)(lastByte & 0xFF)));
	   		//System.out.println(String.format(" Previous number "+ lastByte));
	   		//System.out.println("  Last Byte " + lastByte);
	   		//System.out.print(String.format("Hello %d ",previousIV[7]));
		}
		System.out.println();
		findoutHowtodothis(ciphertext,newCipherText,prefix,previousIV,newlyPreditedIV,XORPredictedIVWithPrefix,lastByte,oneBeforeLastByte);
	/*for (int j = 0; j< 10; j++)
	{	
		for (int p = 0; p < 30; p++ )
		{	
			Byte b = 0; 
			if (lastByte < 128 && lastByte >= 0){			
				 b = Byte.valueOf(lastByte+""); 
				 //System.out.println(String.format("Value of b 1 %02x", b));
			}
			else if (lastByte >= 128 && lastByte < 256) {
				 b = Byte.valueOf((lastByte - 256)+"");
				//System.out.println(String.format("Value of b 2 %02x", b));
			}
			else 
				//System.out.println(String.format("This is impossible. This cannot be a Byte Value %02x", b));
			newlyPreditedIV[7] = b;			
			lastByte++;
			if (lastByte == 256)
				lastByte = 0;
		}
	}*/
		
		/*
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
	    	System.out.println();
	    System.out.print(String.format("%02x ", newCipherText[i]));
	}
	}*/

	
    	
	 }

/*************************************************************************************************************************************************/
	public static void findoutHowtodothis(byte[] ciphertext,byte[]newCipherText,byte[]prefix,byte[]previousIV,byte[]newlyPreditedIV, byte[]XORPredictedIVWithPrefix,int lastByte,int oneBeforeLastByte) throws IOException
	{
		int counterForLastByte = 0;
		int counterForOneBeforeLastByte = 0;
		int predictedIVIntegerValue = 0;
		int previousIVIntegerValue = 0;
		int prefixIntegerValue = 0;
		int xor = 0;
		while (counterForOneBeforeLastByte < 20){
			while (counterForLastByte < 256){
				Byte a = (byte)(newCipherText[6] & 0xFF);
				newlyPreditedIV[6] = a;
				Byte b = (byte)((newCipherText[7] & 0xFF) + 10);
				newlyPreditedIV[7] = b;		
				for (int k=0; k<8; k++){
					predictedIVIntegerValue = (int)newlyPreditedIV[k];
					previousIVIntegerValue = (int)previousIV[k];
					prefixIntegerValue = (int)prefix[k];
					xor = predictedIVIntegerValue^previousIVIntegerValue^prefixIntegerValue;
					byte c = (byte)(0xff & xor);
					XORPredictedIVWithPrefix[k] = c;
				}
				int lengthOfPredictedBlock=callEncrypt(XORPredictedIVWithPrefix,8,newCipherText);
				if (Arrays.equals(Arrays.copyOfRange(ciphertext, 8, 15),Arrays.copyOfRange(newCipherText, 8, 15))){
					System.out.println("WOOOHOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO");				
				}
				else {
					for(int i=0; i<8; i++)
					{
	   					 if (i%8 == 0)
	    						System.out.println();
	  					 System.out.print(String.format("Predicted IV %02x ", newlyPreditedIV[i]));
						 System.out.println(String.format("System IV %02x ", newCipherText[i]));
					}
					System.out.println();				
				}
				counterForLastByte++;
				lastByte++;
			}
			counterForOneBeforeLastByte++;
			oneBeforeLastByte++;
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
                    			System.out.println();
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
                    				System.out.println();
            				System.out.print(String.format("%02x ", newCipherText[i]));
        			}
        		}
		}
		catch (Exception e){
		}
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
