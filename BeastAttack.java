import java.io.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.util.Arrays;

public class BeastAttack
{
    public static void main(String[] args) throws Exception
    {
	byte[] ciphertext=new byte[1024]; // will be plenty big enough
	byte[] newCipherText=new byte[1024]; 
        byte[] prefix = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00};
	byte[] previousIV = new byte[8];
	byte[] newlyPreditedIV = new byte[8];
	byte[] XORPredictedIVWithPrefix = new byte[8];
	byte[] predictedIV = {(byte)0x33,(byte)0xaa,(byte)0x4b,(byte)0x06,(byte)0x1b, (byte)0x50, (byte)0x1b, (byte)0x3d};
	
	// e.g. this prints out the result of an encryption with no prefix
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
