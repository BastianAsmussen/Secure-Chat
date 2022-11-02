package tech.asmussen.chat.util.logs;

public final class ErrorLogger {
	
	public static void logAndExit(String message, Exception e) {
		
		System.out.println(message);
		System.out.println("Error message: " + e.getMessage());
		System.exit(1);
	}
}
