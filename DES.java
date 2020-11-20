import javax.swing.*;  
import java.io.*;
import java.util.* ;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


class DES {
	
	byte[] skey = new byte[1000];
	static byte[] raw;
	
	String skeyString;
	String input, username, password;
	String newUser, newPass;
	String encryptedUsername,decryptedUsername, encryptedPassword, decryptedPassword;
	String encryptedNewUser, decryptedNewUser, encryptedNewPass, decryptedNewPass;
	
	private static File targetFile = new File("Data2.txt");  
	private static Properties properties = new Properties(); 
	private static String newLine = System.lineSeparator(); 
	

	
	static 
	{ 
		targetFile = new File("Data2.txt"); 
		properties = new Properties(); 
		 
		try 
		{ 
			properties.load(new FileInputStream(targetFile.getAbsolutePath())); 
		} 
		 
		catch(IOException ioe) { 
			System.err.println("No file found"); 
		} 
	} 
	
	public DES() {
		try {
			input =JOptionPane.showInputDialog(null,"Welcome to the system^^\n"
												+	  "Please choose an option below(Type in 1 or 2):\n"
												+	  "1. Log in\n"
												+	  "2. Sign up new account\n");
			String key =JOptionPane.showInputDialog(null,"Key: ");
			byte[] ibyteKey = key.getBytes();
			skey = getRawKey(ibyteKey);
			for (byte b : skey) {
	            skeyString = String.format("%02X", b);
			}
			
			JOptionPane.showMessageDialog(null,"DES Symmetric key for both new username and new password: "+skeyString);
			
		//OPTION 1 : IF USER WANT TO LOG IN:
			if(input.equals("1")) { 
				
				username =JOptionPane.showInputDialog(null,"Username: ");
				byte[] ibyteUsername = username.getBytes();
				while (username.length()<6) {
					JOptionPane.showMessageDialog(null,"Username must be at least 6 characters long\n"
													+	"Try again please^^\n");
					username =JOptionPane.showInputDialog(null,"Username: ");
					ibyteUsername = username.getBytes();
				}
				
				password =JOptionPane.showInputDialog(null,"Password: ");
				byte[] ibytePassword = password.getBytes();
				while (password.length()<6) {
					JOptionPane.showMessageDialog(null,"Password must be at least 6 characters long\n"
													+	"Try again please^^\n");
					password =JOptionPane.showInputDialog(null,"Password: ");
					ibytePassword = password.getBytes();
				}
				
				//encrypt the username and password input from user
				//to see if they match any usernames and passwords in database:
				
				
				byte[] ebyteUsername = encrypt(skey, ibyteUsername);
				//byte[] ebyteUsername = encrypt(raw, ibyteUsername);
				for (byte b : ebyteUsername) {
		            encryptedUsername = String.format("%02X", b);
				}
				JOptionPane.showMessageDialog(null,"Encrypted username "+"\n"+encryptedUsername);
				
				byte[] ebytePassword = encrypt(skey, ibytePassword);
				//byte[] ebytePassword = encrypt(raw, ibytePassword);
				for (byte b : ebytePassword) {
		            encryptedPassword = String.format("%02X", b);
				}
				JOptionPane.showMessageDialog(null,"Encrypted password "+"\n"+encryptedPassword);
				
				//end
				Boolean doesTheKeyValuePairExist = checkIfKeyValuePairExists(encryptedUsername,encryptedPassword);
				
				if(!targetFile.exists()) 
					targetFile.createNewFile(); 
				 
				if(doesTheKeyValuePairExist) 
					JOptionPane.showMessageDialog(null, "Log in successfully");
				else { 
					JOptionPane.showMessageDialog(null, "Your username does not match our database"); 
			
				}
				
				byte[] dbyteUsername= decrypt(skey,ebyteUsername);
				String decryptedUsername = new String(dbyteUsername);
				JOptionPane.showMessageDialog(null,"Decrypt username you just entered (not decrypt the database)"+"\n"+decryptedUsername);
				
				byte[] dbytePassword= decrypt(skey,ebytePassword);
				String decryptedPassword = new String(dbytePassword);
				JOptionPane.showMessageDialog(null,"Decrypt password you just entered (not decrypt the database)"+"\n"+decryptedPassword);
		}	//END OPTION 1
		
	//OPTION 2 : IF USER WANTS TO SIGN UP NEW ACCOUNT:
		else if(input.equals("2")) { 
			
			newUser =JOptionPane.showInputDialog(null,"Create a new username:");
			byte[] ibyteNewUser = newUser.getBytes();
			while (newUser.length()<6) {
				JOptionPane.showMessageDialog(null,"Username must be at least 6 characters long\n"
												+	"Try again please^^\n");
				newUser =JOptionPane.showInputDialog(null,"Create a new username:");
				ibyteNewUser = newUser.getBytes();
			}
			
			newPass =JOptionPane.showInputDialog(null,"Create a new password:");
			byte[] ibyteNewPass = newPass.getBytes();
			while (newPass.length()<6) {
				JOptionPane.showMessageDialog(null,"Password must be at least 6 characters long\n"
												+  "Try again please^^\n");
				newPass =JOptionPane.showInputDialog(null,"Create a new password");
				ibyteNewPass = newPass.getBytes();
			}
			
			
	
			byte[] ebyteNewUser = encrypt(skey, ibyteNewUser);
			//byte[] ebyteNewUser = encrypt(raw, ibyteNewUser);
			for (byte b : ebyteNewUser) {
	            encryptedNewUser = String.format("%02X", b);
			}
			JOptionPane.showMessageDialog(null,"Encrypted new username "+"\n"+encryptedNewUser);
			
			byte[] ebyteNewPass = encrypt(skey, ibyteNewPass);
			//byte[] ebyteNewPass = encrypt(raw, ibyteNewPass);
			for (byte b : ebyteNewPass) {
	            encryptedNewPass = String.format("%02X", b);
			}
			JOptionPane.showMessageDialog(null,"Encrypted new password "+"\n"+encryptedNewPass);
			
			
			Boolean doesTheKeyValuePairExist = checkIfKeyValuePairExists(encryptedNewUser, encryptedNewPass);
			
			if(!targetFile.exists()) 
				targetFile.createNewFile(); 
			 
			if(doesTheKeyValuePairExist) 
				JOptionPane.showMessageDialog(null,"Username exists. Please choose another one");
				
			else { 
				try {
		            addNewCredentials(encryptedNewUser, encryptedNewPass);
		            JOptionPane.showMessageDialog(null,"New username and password are encrypted and added to database");
		        }
		        catch(IOException e) {
		        	JOptionPane.showMessageDialog(null, "Exit the program");
		        }
			}//end else
			
			byte[] dbyteNewUser= decrypt(skey,ebyteNewUser);
			String decryptedNewUser = new String(dbyteNewUser);
			JOptionPane.showMessageDialog(null,"Decrypt new username you just entered (not decrypt the database)"+"\n"+decryptedNewUser);
			
			byte[] dbyteNewPass= decrypt(skey,ebyteNewPass);
			String decryptedNewPass = new String(dbyteNewPass);
			JOptionPane.showMessageDialog(null,"Decrypt new password you just entered (not decrypt the database)"+"\n"+decryptedNewPass);
			
		}//end else if OPTION 2
		}//end "big" try
		catch(Exception e){
			JOptionPane.showMessageDialog(null, "Exit the program");
						}
				}

	private static byte[] getRawKey(byte[] seed) throws Exception{
		KeyGenerator kgen = KeyGenerator.getInstance("DES");
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(seed);
		kgen.init(56, sr);
		SecretKey skey = kgen.generateKey();
		raw = skey.getEncoded();
		return raw;
			}
	
	private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "DES");
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		byte[] encrypted = cipher.doFinal(clear);
		return encrypted;
			}
			
	private static byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "DES");
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec);
		byte[] decrypted = cipher.doFinal(encrypted);
		return decrypted;
			}
	
	private static void addNewCredentials(String username, String password) throws IOException { 
		FileWriter writer = new FileWriter(targetFile.getAbsolutePath(), true); 
    	BufferedWriter bw = new BufferedWriter(writer); 
    	bw.write(newLine + username + ":" + password); 
    	bw.close(); 
		} 
 
	private static Boolean checkIfKeyValuePairExists(String encryptedUsername, String encryptedPassword) { 
			for(String key: properties.stringPropertyNames()) 
				if(key.equals(encryptedUsername)&& properties.getProperty(key).equals(encryptedPassword)) 
			return true; 
		return false; 
				
		} 
	
				
	public static void main(String args[]) {
		DES des = new DES();
				}
		
}

		
	

