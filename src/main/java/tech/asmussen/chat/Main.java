package tech.asmussen.chat;

import tech.asmussen.chat.system.Client;
import tech.asmussen.chat.system.Server;
import tech.asmussen.chat.util.security.Security;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Scanner;

public class Main {
	
	public static void main(String[] args) throws UnknownHostException {
		
		Security security = new Security();
		
		Scanner scanner = new Scanner(System.in);
		
		System.out.println("Welcome to the chat program!");
		
		System.out.print("Are you the host or a client? (H/c): ");
		boolean isClient = scanner.nextLine().equalsIgnoreCase("c");
		
		if (isClient) {
			
			System.out.print("Enter the host's IP address: ");
			String ip = scanner.nextLine();
			
			System.out.print("Enter the host's port: ");
			int port = Integer.parseInt(scanner.nextLine());
			
			Client client = new Client();
			
			client.startConnection(ip, port, security);
			
			System.out.println("Connection successful!");
			
			Thread senderThread = new Thread(() -> {
				
				while (true) {
					
					clearLine();
					
					System.out.print("Me: ");
					String message = scanner.nextLine();
					
					if (message.isEmpty() || message.isBlank())
						
						continue;
					
					client.sendMessage(message);
				}
			});
			
			Thread receiverThread = new Thread(() -> {
				
				while (true) {
					
					String message = client.receiveMessage();
					
					clearLine();
					
					System.out.println("Them: " + message);
					System.out.print("\rMe: ");
				}
			});
			
			senderThread.start();
			receiverThread.start();
			
		} else {
			
			System.out.print("Enter the port you want to host on: ");
			int port = Integer.parseInt(scanner.nextLine());
			
			Server server = new Server();
			
			System.out.printf("Waiting for a client on %s:%d...\n", Inet4Address.getLocalHost().getHostAddress(), port);
			server.start(port, security);
			
			System.out.println("Connection successful!");
			
			Thread senderThread = new Thread(() -> {
				
				while (true) {
					
					System.out.print("Me: ");
					String message = scanner.nextLine();
					
					if (message.isEmpty() || message.isBlank())
						continue;
					
					server.sendMessage(message);
				}
			});
			
			Thread receiverThread = new Thread(() -> {
				
				while (true) {
					
					String message = server.receiveMessage();
					
					clearLine();
					
					System.out.println("Them: " + message);
					System.out.print("\rMe: ");
				}
			});
			
			senderThread.start();
			receiverThread.start();
		}
	}
	
	private static void clearLine() {
		
		System.out.print("\r");
		
		for (int i = 0; i < 100; i++) {
			
			System.out.print(" ");
		}
		
		System.out.print("\r");
	}
}
