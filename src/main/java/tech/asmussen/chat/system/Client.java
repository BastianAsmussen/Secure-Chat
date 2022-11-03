package tech.asmussen.chat.system;

import tech.asmussen.chat.util.logs.ErrorLogger;
import tech.asmussen.chat.util.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class Client {
	
	private Security securityInstance;
	
	private Socket clientSocket;
	
	private BufferedReader inputReader;
	private BufferedWriter outputWriter;
	
	private KeyPair keyPair;
	
	private PublicKey serverPublicKey;
	
	public void startConnection(String ip, int port, Security securityInstance) {
		
		try {
			
			this.securityInstance = securityInstance;
			
			clientSocket = new Socket(ip, port);
			
			inputReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			outputWriter = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
			
			keyPair = securityInstance.generateKeyPair();
			
			securityInstance.sendPublicKey(clientSocket, keyPair.getPublic());
			
			serverPublicKey = securityInstance.receivePublicKey(clientSocket);
			
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			
			ErrorLogger.logAndExit("An error occurred while starting the connection!", e);
		}
	}
	
	public void stopConnection() {
		
		try {
			
			clientSocket.close();
			
			inputReader.close();
			outputWriter.close();
			
		} catch (IOException e) {
			
			ErrorLogger.logAndExit("An error occurred while closing the connection!", e);
		}
	}
	
	public void sendMessage(String message) {
		
		try {
			
			String encryptedMessage = securityInstance.encryptMessage(serverPublicKey, message);
			
			outputWriter.write(encryptedMessage);
			outputWriter.newLine();
			outputWriter.flush();
			
		} catch (IOException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException |
		         NoSuchAlgorithmException | InvalidKeyException e) {
			
			ErrorLogger.logAndExit("An error occurred while sending a message!", e);
		}
	}
	
	public String receiveMessage() {
		
		try {
			
			String encryptedMessage = inputReader.readLine();
			
			return securityInstance.decryptMessage(keyPair.getPrivate(), encryptedMessage.getBytes());
			
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
		         IllegalBlockSizeException | BadPaddingException e) {
			
			ErrorLogger.logAndExit("An error occurred while reading a message!", e);
		}
		
		return null;
	}
}
