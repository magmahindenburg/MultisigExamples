package se.moar.bitcoin.multisig;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.DumpedPrivateKey;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptChunk;

import com.google.common.collect.ImmutableList;

@SuppressWarnings("unused")
public class MultisigPresentation {

	// static final NetworkParameters params = TestNet3Params.get();
	static final NetworkParameters params = MainNetParams.get();
	static final Coin transactionFee = Coin.valueOf(10000); // 0.000 100 00 BTC
	
	/**
	 * @param args
	 * @throws AddressFormatException 
	 */
	public static void main(String[] args) throws AddressFormatException {
		
		generateMultisig();
		String getSignedTransaction = signFirstTime();
		signSecondTime(getSignedTransaction);

	}
	
	private static void generateMultisig() throws AddressFormatException
	{
		ECKey key1 = createKeyFromSha256Passphrase("Super secret key 1");
		/*
		DumpedPrivateKey privateKey1 = key1.getPrivateKeyEncoded(params);
		Address address1 = key1.toAddress(params);
		System.out.println(byteArrayToHex(key1.getPubKey()));	// Print the public key
		System.out.println(privateKey1.toString() ); 			// Print the private key if you feel like it
		*/
		
		ECKey key2 = createKeyFromSha256Passphrase("Super secret key 2");
		/*
		DumpedPrivateKey privateKey2 = key2.getPrivateKeyEncoded(params);
		Address address2 = key1.toAddress(params);
		System.out.println(byteArrayToHex(key2.getPubKey()));	// Print the public key
		System.out.println(privateKey2.toString()); 			// Print the private key if you feel like it
		*/
		
		ECKey key3 = createKeyFromSha256Passphrase("Super secret key 3");
		/*
		DumpedPrivateKey privateKey3 = key3.getPrivateKeyEncoded(params);
		Address address3 = key1.toAddress(params);
		System.out.println(byteArrayToHex(key3.getPubKey()));		// Print the public key
		System.out.println(privateKey3.toString()); 				// Print the private key if you feel like it
		*/
		
		// Create a 2-of-3 multisig redeemScript (output script)
		// The private keys are not needed. The redeem script can be created with only public keys
		// Create a public key using new ECKey(null, publicKey)
		List<ECKey> keys = ImmutableList.of(key1, key2, key3);
		Script redeemScript = ScriptBuilder.createRedeemScript(2, keys);
		Script script = ScriptBuilder.createP2SHOutputScript(redeemScript);
		
		// Print the scripthash
		System.out.println("Redeem script: " + byteArrayToHex(redeemScript.getProgram()));
		
		// Print out our newly generated multisig address so people can send us coins
		Address multisig = Address.fromP2SHScript(params, script);
		System.out.println("Multisig address: " + multisig.toString());

	}
	
	private static String signFirstTime() throws AddressFormatException
	{
		// Generate a private key from our super secret passphrase
		ECKey key1 = createKeyFromSha256Passphrase("Super secret key 1");
		
		// Use the redeem script we have saved somewhere to start building the transaction
		Script redeemScript = new Script(hexStringToByteArray("524104..."));
		
		// Start building the transaction by adding the unspent inputs we want to use
		Transaction spendTx = new Transaction(params);
		ScriptBuilder scriptBuilder = new ScriptBuilder();
		scriptBuilder.data(new String("a91.....").getBytes());
		TransactionInput input = spendTx.addInput(new Sha256Hash("cc1..."), 1, scriptBuilder.build());
		
		// Add outputs to the person receiving bitcoins
		Address receiverAddress = new Address(params, "1......");
		Coin charge = Coin.valueOf(10000); // 0.1 mBTC
		Script outputScript = ScriptBuilder.createOutputScript(receiverAddress);
        spendTx.addOutput(charge, outputScript);
        
        // Sign the first part of the transaction using private key #1
     	Sha256Hash sighash = spendTx.hashForSignature(0, redeemScript, Transaction.SigHash.ALL, false);
     	ECKey.ECDSASignature ecdsaSignature = key1.sign(sighash);
     	TransactionSignature transactionSignarture = new TransactionSignature(ecdsaSignature, Transaction.SigHash.ALL, false);

        // Create p2sh multisig input script
        Script inputScript = ScriptBuilder.createP2SHMultiSigInputScript(Arrays.asList(transactionSignarture), redeemScript);

		// Add the script signature to the input
		input.setScriptSig(inputScript);
		System.out.println(byteArrayToHex(spendTx.bitcoinSerialize()));
				
		return byteArrayToHex(spendTx.bitcoinSerialize());
	}
	
	private static String signSecondTime(String transactionString)
	{
		// Take the hex string we got from the other part and convert it into a Transaction object
		Transaction spendTx = new Transaction(params, hexStringToByteArray(transactionString));
		
		// Get the input chunks
		Script inputScript = spendTx.getInput(0).getScriptSig();
		List<ScriptChunk> scriptChunks = inputScript.getChunks();
		
		// Create a list of all signatures. Start by extracting the existing ones from the list of script schunks.
		// The last signature in the script chunk list is the redeemScript
		List<TransactionSignature> signatureList = new ArrayList<TransactionSignature>();
		Iterator<ScriptChunk> iterator = scriptChunks.iterator();
		Script redeemScript = null;
		
		while (iterator.hasNext())
		{
			ScriptChunk chunk = iterator.next();
			
			if (iterator.hasNext() && chunk.opcode != 0)
			{
				TransactionSignature transactionSignarture = TransactionSignature.decodeFromBitcoin(chunk.data, false);
				signatureList.add(transactionSignarture);
			} else
			{
				redeemScript = new Script(chunk.data);
			}
		}
		
		// Create the sighash using the redeem script
     	Sha256Hash sighash = spendTx.hashForSignature(0, redeemScript, Transaction.SigHash.ALL, false);
     	ECKey.ECDSASignature secondSignature;
		
     	// Take out the key and sign the signhash
     	ECKey key2 = createKeyFromSha256Passphrase("Super secret key 2");
     	secondSignature = key2.sign(sighash);
     	
     	// Add the second signature to the signature list
		TransactionSignature transactionSignarture = new TransactionSignature(secondSignature, Transaction.SigHash.ALL, false);
		signatureList.add(transactionSignarture);
		
		// Rebuild p2sh multisig input script
        inputScript = ScriptBuilder.createP2SHMultiSigInputScript(signatureList, redeemScript);
        spendTx.getInput(0).setScriptSig(inputScript);
        
        System.out.println(byteArrayToHex(spendTx.bitcoinSerialize()));

		return byteArrayToHex(spendTx.bitcoinSerialize());
	}
	
	/**
	 * Method to convert a passphrase similar to brainwallet.org, to a bitcoin private key. This method of creating an ECKey is deprecated 
	 * @param secret
	 * @return
	 */
	public static ECKey createKeyFromSha256Passphrase(String secret) {
        byte[] hash = null;

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(secret.getBytes("UTF-8"));
            hash = md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        @SuppressWarnings("deprecation")
		ECKey key = new ECKey(hash, (byte[])null);
        return key;
    }
	
	/**
	 * Method to convert a passphrase similar to a bitcoin private key. Not the same as brainwallet.org
	 * @param secret
	 * @return
	 */
	public static ECKey createFromPassphrase(String secret) {
        byte[] hash = null;

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(secret.getBytes("UTF-8"));
            hash = md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        ECKey key = new ECKey(new SecureRandom(hash));
        return key;
    }
	
	/**
	 * Method to convert a byte array to human readable hex string
	 * @param a
	 * @return hex string
	 */
	public static String byteArrayToHex(byte[] a) {
		   StringBuilder sb = new StringBuilder(a.length * 2);
		   for(byte b: a)
		      sb.append(String.format("%02x", b & 0xff));
		   return sb.toString();
	}
	
	/**
	 * Method to convert a human readable hex string to a byte array
	 * @param s
	 * @return byte array
	 */
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}

}
