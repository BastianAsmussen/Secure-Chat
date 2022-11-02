package tech.asmussen.chat.system;

import tech.asmussen.chat.util.logs.ErrorLogger;
import tech.asmussen.chat.util.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class Server {
	
	private Security securityInstance;
	
	private ServerSocket serverSocket;
	private Socket clientSocket;
	
	private BufferedReader inputReader;
	private BufferedWriter outputWriter;
	
	private KeyPair keyPair;
	
	private PublicKey clientPublicKey;
	
	public void start(int port, Security securityInstance) {
		
		try {
			
			this.securityInstance = securityInstance;
			
			serverSocket = new ServerSocket(port);
			clientSocket = serverSocket.accept();
			
			inputReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			outputWriter = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
			
			keyPair = securityInstance.generateKeyPair();
			
			securityInstance.sendPublicKey(clientSocket, keyPair.getPublic());
			
			clientPublicKey = securityInstance.receivePublicKey(clientSocket);
			
		} catch (IOException | IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			
			ErrorLogger.logAndExit("An error occurred while starting the server", e);
		}
	}
	
	public void stop() {
		
		try {
			
			clientSocket.close();
			serverSocket.close();
			
			inputReader.close();
			outputWriter.close();
			
		} catch (IOException e) {
			
			ErrorLogger.logAndExit("An error occurred while stopping the server", e);
		}
	}
	
	public void sendMessage(String message) {
		/*
		try {
			
			byte[] encryptedMessage = securityInstance.encryptMessage(clientPublicKey, message);
			
			outputWriter.write(new String(encryptedMessage));
			outputWriter.newLine();
			outputWriter.flush();
			
		} catch (IOException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException |
		         NoSuchAlgorithmException | InvalidKeyException e) {
			
			ErrorLogger.logAndExit("An error occurred while sending a message!", e);
		}
		 */
	}
	
	public String receiveMessage() {
		/*
		try {
			
			String encryptedMessage = inputReader.readLine();
			byte[] decryptedMessage = securityInstance.decryptMessage(keyPair.getPrivate(), encryptedMessage.getBytes());
			
			return new String(decryptedMessage);
			
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
		         IllegalBlockSizeException | BadPaddingException e) {
			
			e.printStackTrace();
			
			ErrorLogger.logAndExit("An error occurred while reading a message!", e);
		}
		
		 */
		return null;
	}
}
