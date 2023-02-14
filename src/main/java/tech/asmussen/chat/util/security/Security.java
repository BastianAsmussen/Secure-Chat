package tech.asmussen.chat.util.security;

import com.lambdaworks.crypto.SCryptUtil;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import lombok.Data;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * A utility class for all systems involving security used by Bastian Asmussen.
 *
 * @author Bastian Almar Wolsgaard Asmussen (BastianA)
 * @author Casper Agerskov Madsen (consoleBeep)
 * @version 1.1.1
 * @see #DEFAULT_KEY_SIZE
 * @see #DEFAULT_KEY_PAIR_ALGORITHM
 * @see #DEFAULT_PUBLIC_KEY_DELIMITERS
 * @see #DEFAULT_CIPHER_ALGORITHM
 * @see #DEFAULT_CPU_COST
 * @see #DEFAULT_MEMORY_COST
 * @see #DEFAULT_PARALLELIZATION
 * @see #DEFAULT_VALIDATION_URL
 * @see #DEFAULT_MAX_PASSWORD_LENGTH
 * @see #DEFAULT_MIN_PASSWORD_LENGTH
 * @see #Security(int, String, String[], String, int, int, int, String, String, String, String, int, int, String)
 * @see #Security()  Security
 * @see SecurityBuilder
 * @see #generateKeyPair()
 * @see #generateKeyPair(int, String)
 * @see #sendPublicKey(Socket, PublicKey)
 * @see #receivePublicKey(Socket)
 * @see #decodePublicKey(String)
 * @see #decodePrivateKey(String)
 * @see #generateCipher(PublicKey)
 * @see #generateCipher(PublicKey, String)
 * @see #encryptMessage(Cipher, byte[])
 * @see #encryptMessage(PublicKey, String)
 * @see #decryptMessage(PrivateKey, byte[])
 * @see #decryptMessage(PrivateKey, String)
 * @see #generateHash(String)
 * @see #generateHash(String, int, int, int)
 * @see #compareHash(String, String)
 * @see #generatePassword(int, boolean, boolean, boolean, boolean)
 * @see #hasInternet()
 * @see #hasInternet(URL)
 * @see #generate2FA()
 * @see #validate2FA(String, String)
 * @see #validate2FA(String, int)
 * @see #isValidPassword(String)
 * @see #isValidEmail(String)
 * @see #isValidCreditCard(String)
 * @since 1.0.0
 */
@Data
public final class Security {
	
	/**
	 * The default key size for the key pair generator.
	 *
	 * @see #generateKeyPair()
	 * @since 1.1.0
	 */
	public static final int DEFAULT_KEY_SIZE = 2_048;
	
	/**
	 * The default algorithm for the key pair generator.
	 *
	 * @see #generateKeyPair()
	 * @since 1.1.0
	 */
	public static final String DEFAULT_KEY_PAIR_ALGORITHM = "RSA";
	
	/**
	 * The default algorithm for the cipher generator.
	 *
	 * @see #generateCipher(PublicKey)
	 * @see #decryptMessage(PrivateKey, byte[])
	 * @since 1.1.0
	 */
	public static final String DEFAULT_CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
	
	/**
	 * The default CPU cost for the hash generator.
	 *
	 * @see #generateHash(String)
	 * @since 1.1.0
	 */
	public static final int DEFAULT_CPU_COST = 16;
	
	/**
	 * The default memory cost for the hash generator.
	 *
	 * @see #generateHash(String)
	 * @since 1.1.0
	 */
	public static final int DEFAULT_MEMORY_COST = 16;
	
	/**
	 * The default parallelization for the hash generator.
	 *
	 * @see #generateHash(String)
	 * @since 1.1.0
	 */
	public static final int DEFAULT_PARALLELIZATION = 1;
	
	/**
	 * The default hash algorithm for the hasInternet() method.
	 *
	 * @see #hasInternet()
	 * @since 1.1.0
	 */
	public static final String DEFAULT_VALIDATION_URL = "https://www.google.com";
	
	/**
	 * The maximum length of a password.
	 *
	 * @see #isValidPassword(String)
	 * @see #generatePassword(int, boolean, boolean, boolean, boolean)
	 * @since 1.0.2
	 */
	public static final int DEFAULT_MAX_PASSWORD_LENGTH = 128;
	
	/**
	 * The minimum length of a password.
	 *
	 * @see #isValidPassword(String)
	 * @see #generatePassword(int, boolean, boolean, boolean, boolean)
	 * @since 1.0.2
	 */
	public static final int DEFAULT_MIN_PASSWORD_LENGTH = 8;
	
	/**
	 * The lowercase letters that are allowed in a password.
	 *
	 * @see #generatePassword(int, boolean, boolean, boolean, boolean)
	 * @since 1.0.2
	 */
	public static final String DEFAULT_ALLOWED_LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz";
	
	/**
	 * The uppercase letters that are allowed in a password.
	 *
	 * @see #generatePassword(int, boolean, boolean, boolean, boolean)
	 * @since 1.0.2
	 */
	public static final String DEFAULT_ALLOWED_UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	
	/**
	 * The numbers that are allowed in a password.
	 *
	 * @see #generatePassword(int, boolean, boolean, boolean, boolean)
	 * @since 1.0.2
	 */
	public static final String DEFAULT_ALLOWED_NUMBERS = "1234567890";
	
	/**
	 * The special characters that are allowed in a password.
	 *
	 * @see #generatePassword(int, boolean, boolean, boolean, boolean)
	 * @since 1.0.2
	 */
	public static final String DEFAULT_ALLOWED_SPECIAL_CHARACTERS = "@$!%*?&";
	
	/**
	 * The delimiting lines used by the public keys when sent.
	 *
	 * @since 1.1.1
	 */
	public static final String[] DEFAULT_PUBLIC_KEY_DELIMITERS = {"---BEGIN PUBLIC KEY---", "---END PUBLIC KEY---"};
	
	private final int keySize;
	
	private final String keyPairAlgorithm;
	private final String[] publicKeyDelimiters;
	
	private final String cipherAlgorithm;
	
	private final int cpuCost;
	private final int memoryCost;
	private final int parallelization;
	
	private final String allowedLowercaseLetters;
	private final String allowedUppercaseLetters;
	private final String allowedSpecialCharacters;
	private final String allowedNumbers;
	private final int minPasswordLength;
	private final int maxPasswordLength;
	
	private final String validationURL;
	
	/**
	 * Makes a new instance of the Security class with the given arguments.
	 *
	 * @param keySize                  The key size for the key pair generator.
	 * @param keyPairAlgorithm         The algorithm for the key pair generator.
	 * @param publicKeyDelimiters      The delimiting lines used by the public keys when sent.
	 * @param cipherAlgorithm          The algorithm for the cipher generator.
	 * @param cpuCost                  The CPU cost for the hash generator.
	 * @param memoryCost               The memory cost for the hash generator.
	 * @param parallelization          The parallelization for the hash generator.
	 * @param allowedLowercaseLetters  The lowercase letters that are allowed in a password.
	 * @param allowedUppercaseLetters  The uppercase letters that are allowed in a password.
	 * @param allowedSpecialCharacters The special characters that are allowed in a password.
	 * @param allowedNumbers           The numbers that are allowed in a password.
	 * @param minPasswordLength        The minimum length of a password.
	 * @param maxPasswordLength        The maximum length of a password.
	 * @param validationURL            The URL to use for the hasInternet() method.
	 * @since 1.1.1
	 */
	public Security(int keySize, String keyPairAlgorithm, String[] publicKeyDelimiters, String cipherAlgorithm, int cpuCost, int memoryCost, int parallelization, String allowedLowercaseLetters, String allowedUppercaseLetters, String allowedSpecialCharacters, String allowedNumbers, int minPasswordLength, int maxPasswordLength, String validationURL) {
		
		this.keySize = keySize;
		
		this.keyPairAlgorithm = keyPairAlgorithm;
		this.publicKeyDelimiters = publicKeyDelimiters;
		
		this.cipherAlgorithm = cipherAlgorithm;
		
		this.cpuCost = cpuCost;
		this.memoryCost = memoryCost;
		this.parallelization = parallelization;
		
		this.allowedLowercaseLetters = allowedLowercaseLetters;
		this.allowedUppercaseLetters = allowedUppercaseLetters;
		this.allowedSpecialCharacters = allowedSpecialCharacters;
		this.allowedNumbers = allowedNumbers;
		this.minPasswordLength = minPasswordLength;
		this.maxPasswordLength = maxPasswordLength;
		
		this.validationURL = validationURL;
	}
	
	/**
	 * Makes a new instance of the Security class with all default values.
	 *
	 * @see #Security(int, String, String[], String, int, int, int, String, String, String, String, int, int, String)
	 * @see #DEFAULT_KEY_SIZE
	 * @see #DEFAULT_KEY_PAIR_ALGORITHM
	 * @see #DEFAULT_PUBLIC_KEY_DELIMITERS
	 * @see #DEFAULT_CIPHER_ALGORITHM
	 * @see #DEFAULT_CPU_COST
	 * @see #DEFAULT_MEMORY_COST
	 * @see #DEFAULT_PARALLELIZATION
	 * @see #DEFAULT_ALLOWED_LOWERCASE_LETTERS
	 * @see #DEFAULT_ALLOWED_UPPERCASE_LETTERS
	 * @see #DEFAULT_ALLOWED_SPECIAL_CHARACTERS
	 * @see #DEFAULT_ALLOWED_NUMBERS
	 * @see #DEFAULT_MIN_PASSWORD_LENGTH
	 * @see #DEFAULT_MAX_PASSWORD_LENGTH
	 * @see #DEFAULT_VALIDATION_URL
	 * @since 1.1.1
	 */
	public Security() {
		
		this(DEFAULT_KEY_SIZE, DEFAULT_KEY_PAIR_ALGORITHM, DEFAULT_PUBLIC_KEY_DELIMITERS, DEFAULT_CIPHER_ALGORITHM, DEFAULT_CPU_COST, DEFAULT_MEMORY_COST, DEFAULT_PARALLELIZATION, DEFAULT_ALLOWED_LOWERCASE_LETTERS, DEFAULT_ALLOWED_UPPERCASE_LETTERS, DEFAULT_ALLOWED_SPECIAL_CHARACTERS, DEFAULT_ALLOWED_NUMBERS, DEFAULT_MIN_PASSWORD_LENGTH, DEFAULT_MAX_PASSWORD_LENGTH, DEFAULT_VALIDATION_URL);
	}
	
	private static boolean isEven(int n) {
		
		return n % 2 == 0;
	}
	
	private static String filter(String str) {
		
		final String specialRegExCharacters = ".[]{}()<>*+-=!?^$|";
		
		StringBuilder filteredString = new StringBuilder();
		
		for (char c : str.toCharArray()) {
			
			if (specialRegExCharacters.contains(String.valueOf(c))) {
				
				filteredString.append("\\").append(c);
				
			} else {
				
				filteredString.append(c);
			}
		}
		
		return filteredString.toString();
	}
	
	/**
	 * Generate a keypair of a certain size and return it.
	 *
	 * @return A keypair of the size specified in the constructor to be used along with other methods.
	 * @throws NoSuchAlgorithmException If the algorithm is not supported throw this exception.
	 * @see #generateKeyPair(int, String)
	 * @see #keySize
	 * @see #keyPairAlgorithm
	 * @since 1.0.0
	 */
	public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		
		return generateKeyPair(keySize, keyPairAlgorithm);
	}
	
	/**
	 * Generate a keypair of size n and return it.
	 *
	 * @param keySize   Size of keypair, note: the bigger the key size the longer the generation time.
	 * @param algorithm The algorithm to use for the keypair generation.
	 * @return A keypair of size n to be used along with other methods.
	 * @throws NoSuchAlgorithmException If the algorithm is not supported throw this exception.
	 * @since 1.0.0
	 */
	public KeyPair generateKeyPair(int keySize, String algorithm) throws NoSuchAlgorithmException {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		
		keyPairGenerator.initialize(keySize);
		
		return keyPairGenerator.generateKeyPair();
	}
	
	/**
	 * Send the generated public key to the given socket.
	 *
	 * @param socket    The socket to send the public key to.
	 * @param publicKey The public key to send.
	 * @throws IOException               If an I/O error occurs.
	 * @throws IndexOutOfBoundsException If {@link #publicKeyDelimiters} is not of length 2.
	 * @since 1.1.1
	 */
	public void sendPublicKey(Socket socket, PublicKey publicKey) throws IOException, IndexOutOfBoundsException {
		
		BufferedWriter output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
		
		output.write(publicKeyDelimiters[0]);
		output.newLine();
		
		output.write(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
		output.newLine();
		
		output.write(publicKeyDelimiters[1]);
		output.newLine();
		
		output.flush();
	}
	
	/**
	 * Receive the public key from the given socket.
	 *
	 * @param socket The socket to receive the public key from.
	 * @return The public key, or null if the public key could not be received.
	 * @throws IOException               If an I/O error occurs.
	 * @throws NoSuchAlgorithmException  If the {@link #keyPairAlgorithm} is not supported.
	 * @throws InvalidKeySpecException   If the public key is invalid.
	 * @throws IndexOutOfBoundsException If {@link #publicKeyDelimiters} is not of length 2.
	 * @since 1.1.1
	 */
	public PublicKey receivePublicKey(Socket socket) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, IndexOutOfBoundsException {
		
		BufferedReader inputReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		
		// Read the public key from the other side.
		StringBuilder publicKeyString = new StringBuilder();
		
		String line;
		while ((line = inputReader.readLine()) != null) {
			
			if (line.equals(publicKeyDelimiters[0])) {
				
				publicKeyString = new StringBuilder();
				
			} else if (line.equals(publicKeyDelimiters[1])) {
				
				break;
				
			} else {
				
				publicKeyString.append(line);
			}
		}
		
		return decodePublicKey(publicKeyString.toString());
	}
	
	/**
	 * Based on a Base64 encoded public key decode it and return it.
	 *
	 * @param rawPublicKey The Base64 encoded public key.
	 * @return The decoded public key.
	 * @throws NoSuchAlgorithmException If the algorithm is not supported throw this exception.
	 * @throws InvalidKeySpecException  If the key is invalid throw this exception.
	 * @see #keyPairAlgorithm
	 * @since 1.1.1
	 */
	public PublicKey decodePublicKey(String rawPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		byte[] decodedPublicKey = Base64.getDecoder().decode(rawPublicKey);
		
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedPublicKey);
		KeyFactory keyFactory = KeyFactory.getInstance(keyPairAlgorithm);
		
		return keyFactory.generatePublic(keySpec);
	}
	
	/**
	 * Based on a Base64 encoded private key decode it and return it.
	 *
	 * @param rawPrivateKey The Base64 encoded private key.
	 * @return The decoded private key.
	 * @throws NoSuchAlgorithmException If the algorithm is not supported throw this exception.
	 * @throws InvalidKeySpecException  If the key is invalid throw this exception.
	 * @see #keyPairAlgorithm
	 * @since 1.1.1
	 */
	public PrivateKey decodePrivateKey(String rawPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		byte[] decodedPrivateKey = Base64.getDecoder().decode(rawPrivateKey);
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
		KeyFactory keyFactory = KeyFactory.getInstance(keyPairAlgorithm);
		
		return keyFactory.generatePrivate(keySpec);
	}
	
	/**
	 * Generate a cipher from the given public key and return it as Cipher.
	 *
	 * @param publicKey Used for cipher generation.
	 * @return A cipher used for encryption of a message.
	 * @throws NoSuchPaddingException   If the cipher is not supported throw this exception.
	 * @throws NoSuchAlgorithmException If the cipher is not supported throw this exception.
	 * @throws InvalidKeyException      If the given public key is invalid throw this exception.
	 * @see #cipherAlgorithm
	 * @see #generateCipher(PublicKey, String)
	 * @since 1.0.0
	 */
	public Cipher generateCipher(PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
		
		return generateCipher(publicKey, cipherAlgorithm);
	}
	
	/**
	 * Generate a cipher from the given public key and return it as Cipher.
	 *
	 * @param publicKey Used for cipher generation.
	 * @param algorithm The algorithm used for cipher generation.
	 * @return A cipher used for encryption of a message.
	 * @throws NoSuchPaddingException   If the cipher is not supported throw this exception.
	 * @throws NoSuchAlgorithmException If the cipher is not supported throw this exception.
	 * @throws InvalidKeyException      If the given public key is invalid throw this exception.
	 * @since 1.0.0
	 */
	public Cipher generateCipher(PublicKey publicKey, String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
		
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		
		return cipher;
	}
	
	/**
	 * Encrypt the given input with the given public key.
	 *
	 * @param publicKey Public key used for decryption of message.
	 * @param input     The input used to encrypt as a String.
	 * @return The encrypted input as a byte array.
	 * @throws IllegalBlockSizeException If the input is too large throw this exception.
	 * @throws BadPaddingException       If the input is not padded correctly throw this exception.
	 * @throws InvalidKeyException       If the given public key is invalid throw this exception.
	 * @throws NoSuchPaddingException    If the cipher is not supported throw this exception.
	 * @throws NoSuchAlgorithmException  If the cipher is not supported throw this exception.
	 * @throws InvalidKeyException       If the given public key is invalid throw this exception.
	 * @see #encryptMessage(Cipher, byte[])
	 * @since 1.0.0
	 */
	public String encryptMessage(PublicKey publicKey, String input) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
		
		Cipher cipher = generateCipher(publicKey);
		
		return encryptMessage(cipher, input.getBytes(StandardCharsets.UTF_8));
	}
	
	/**
	 * Encrypt the given input with the given cipher.
	 *
	 * @param cipher The cipher used for encryption of message.
	 * @param input  The input used to encrypt as a byte array.
	 * @return The encrypted input as a byte array.
	 * @throws IllegalBlockSizeException If the input is too large throw this exception.
	 * @throws BadPaddingException       If the input is not padded correctly throw this exception.
	 * @since 1.0.0
	 */
	private String encryptMessage(Cipher cipher, byte[] input) throws IllegalBlockSizeException, BadPaddingException {
		
		return new String(Base64.getEncoder().encode(cipher.doFinal(input)));
	}
	
	/**
	 * Decrypt the given input with the given private key.
	 *
	 * @param privateKey Private key used for decryption of message.
	 * @param input      Input message as a byte array.
	 * @return The decrypted message as a byte array.
	 * @throws NoSuchAlgorithmException  If the algorithm is not supported throw this exception.
	 * @throws NoSuchPaddingException    If the padding is not supported throw this exception.
	 * @throws InvalidKeyException       If the key is invalid throw this exception.
	 * @throws IllegalBlockSizeException If the block size is invalid throw this exception.
	 * @throws BadPaddingException       If the padding is invalid throw this exception.
	 * @see #decryptMessage(PrivateKey, byte[])
	 * @since 1.0.0
	 */
	public String decryptMessage(PrivateKey privateKey, String input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		return decryptMessage(privateKey, input.getBytes());
	}
	
	/**
	 * Decrypt the given input with the given private key.
	 *
	 * @param privateKey Private key used for decryption of message.
	 * @param input      Input message as a byte array.
	 * @return The decrypted message as a byte array.
	 * @throws NoSuchAlgorithmException  If the algorithm is not supported throw this exception.
	 * @throws NoSuchPaddingException    If the padding scheme is not supported throw this exception.
	 * @throws InvalidKeyException       If the key is invalid throw this exception.
	 * @throws IllegalBlockSizeException If the size of the input is not a multiple of the block size throw this exception.
	 * @throws BadPaddingException       If the padding bytes are incorrect throw this exception.
	 * @see #cipherAlgorithm
	 * @since 1.0.0
	 */
	public String decryptMessage(PrivateKey privateKey, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher cipher = Cipher.getInstance(cipherAlgorithm);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		
		return new String(cipher.doFinal(Base64.getDecoder().decode(input)));
	}
	
	/**
	 * Generate a hashed password from plain text and return it.
	 *
	 * @param str Plain text token / password.
	 * @return Returns the hashed password from the plain text password.
	 * @see #cpuCost
	 * @see #memoryCost
	 * @see #parallelization
	 * @see #generateHash(String, int, int, int)
	 * @since 1.0.0
	 */
	public String generateHash(String str) {
		
		return generateHash(str, cpuCost, memoryCost, parallelization);
	}
	
	/**
	 * Generate a hashed password from plain text and return it.
	 *
	 * @param str Plain text token / password.
	 * @param n   CPU cost parameter.
	 * @param r   Memory cost parameter.
	 * @param p   Parallelization parameter.
	 * @return Returns the hashed password from the plain text password.
	 * @since 1.0.0
	 */
	public String generateHash(String str, int n, int r, int p) {
		
		return SCryptUtil.scrypt(str, n, r, p);
	}
	
	/**
	 * Compare the given string against the given hash and return the match as boolean.
	 *
	 * @param str  The plain text token / password from the user.
	 * @param hash The hash from the database.
	 * @return True if the string matches the hash otherwise false.
	 * @since 1.0.0
	 */
	public boolean compareHash(String str, String hash) {
		
		return SCryptUtil.check(str, hash);
	}
	
	/**
	 * Generate a 2FA secret key and return it.
	 *
	 * @return The generated secret key.
	 * @since 1.0.0
	 */
	public String generate2FA() {
		
		return new GoogleAuthenticator().createCredentials().getKey();
	}
	
	/**
	 * Validate the code with the secret key and return the match as boolean.
	 *
	 * @param secretKey The secret key used for generating the code.
	 * @param code      The 6-digit code used for validation.
	 * @return True if the code matches the secret key otherwise false.
	 * @see #validate2FA(String, int)
	 * @since 1.0.0
	 */
	public boolean validate2FA(String secretKey, String code) {
		
		if (!code.matches("\\d{6}$")) return false;
		
		return validate2FA(secretKey, Integer.parseInt(code));
	}
	
	/**
	 * Validate the code with the secret key and return the match as boolean.
	 *
	 * @param secretKey The secret key used for generating the code.
	 * @param code      The 6-digit code used for validation.
	 * @return True if the code matches the secret key otherwise false.
	 * @since 1.0.0
	 */
	public boolean validate2FA(String secretKey, int code) {
		
		return new GoogleAuthenticator().authorize(secretKey, code);
	}
	
	/**
	 * Generate a password of a certain length.
	 *
	 * @param length               How long should the password be?
	 * @param useLowerCaseLetters  Should the password contain lowercase letters?
	 * @param useUpperCaseLetters  Should the password contain uppercase letters?
	 * @param useNumbers           Should the password contain digits?
	 * @param useSpecialCharacters Should the password contain symbols
	 * @return The generated password.
	 * @throws IllegalArgumentException If the length is not between throw this exception.
	 * @see #allowedLowercaseLetters
	 * @see #allowedUppercaseLetters
	 * @see #allowedNumbers
	 * @see #allowedSpecialCharacters
	 * @see #minPasswordLength
	 * @see #maxPasswordLength
	 * @since 1.0.0
	 */
	public String generatePassword(int length, boolean useLowerCaseLetters, boolean useUpperCaseLetters, boolean useNumbers, boolean useSpecialCharacters) throws IllegalArgumentException {
		
		if (!(length >= minPasswordLength) || !(length <= maxPasswordLength) || !useLowerCaseLetters && !useUpperCaseLetters && !useNumbers && !useSpecialCharacters) {
			
			throw new IllegalArgumentException("Invalid arguments provided!");
		}
		
		StringBuilder passwordBuilder = new StringBuilder();
		
		String charset = "";
		
		if (useLowerCaseLetters) charset += allowedLowercaseLetters;
		if (useUpperCaseLetters) charset += allowedUppercaseLetters;
		if (useNumbers) charset += allowedNumbers;
		if (useSpecialCharacters) charset += allowedSpecialCharacters;
		
		for (int i = 0; i < length; i++) {
			
			passwordBuilder.append(charset.charAt(new SecureRandom().nextInt(charset.length())));
		}
		
		// Check if the generated password is valid.
		if (!isValidPassword(passwordBuilder.toString())) {
			
			return generatePassword(length, useLowerCaseLetters, useUpperCaseLetters, useNumbers, useSpecialCharacters);
		}
		
		return passwordBuilder.toString();
	}
	
	/**
	 * Checks if the application has a connection to the internet.
	 *
	 * @return True if the application has a connection to the internet otherwise it returns false.
	 * @throws IOException If an error occurs while checking the connection throw this exception.
	 * @see #hasInternet(URL)
	 * @see #validationURL
	 * @since 1.0.0
	 */
	public boolean hasInternet() throws IOException {
		
		return hasInternet(new URL(validationURL));
	}
	
	/**
	 * Checks if the application has a connection to the internet.
	 *
	 * @param url The url to check the connection against.
	 * @return True if the application has a connection to the internet otherwise it returns false.
	 * @throws IOException              If an error occurs while checking the connection throw this exception.
	 * @throws IllegalArgumentException If the url parameter is null throw this exception.
	 * @since 1.0.0
	 */
	public boolean hasInternet(URL url) throws IOException {
		
		if (url == null) throw new IllegalArgumentException("The URL cannot be null!");
		
		final URLConnection connection = url.openConnection();
		
		connection.connect();
		connection.getInputStream().close();
		
		return true;
	}
	
	/**
	 * Match the plain text password against a regular expression and return the result.
	 * Password must contain one lowercase letter.
	 * Password must contain one uppercase letter.
	 * Password must contain one digit.
	 * Password must contain a symbol.
	 * Password must be a certain length.
	 *
	 * @param plaintextPassword The password of the user.
	 * @return True if it is a valid password otherwise it returns false.
	 * @see #allowedLowercaseLetters
	 * @see #allowedUppercaseLetters
	 * @see #allowedNumbers
	 * @see #allowedSpecialCharacters
	 * @see #minPasswordLength
	 * @see #maxPasswordLength
	 * @since 1.0.0
	 */
	public boolean isValidPassword(String plaintextPassword) {
		
		// Compile a RegEx pattern based on the allowed characters.
		String filteredLowercaseLetters = filter(allowedLowercaseLetters);
		String filteredUppercaseLetters = filter(allowedUppercaseLetters);
		String filteredNumbers = filter(allowedNumbers);
		String filteredSpecialCharacters = filter(allowedSpecialCharacters);
		
		final String rawPattern = "^(?=.*[%s])(?=.*[%s])(?=.*[%s])(?=.*[%s])[%s%s%s%s]{%d,%d}$".formatted(filteredLowercaseLetters, filteredUppercaseLetters, filteredNumbers, filteredSpecialCharacters, filteredLowercaseLetters, filteredUppercaseLetters, filteredNumbers, filteredSpecialCharacters, minPasswordLength, maxPasswordLength);
		
		return plaintextPassword.matches(rawPattern);
	}
	
	/**
	 * Match the given email against a regular expression and return the result.
	 * Email must contain only one @.
	 * Email cannot start with the @ sign.
	 * Email must end with an address such as '.com'
	 *
	 * @param email The email of the user.
	 * @return True if it is a valid email otherwise it returns false.
	 * @since 1.0.0
	 */
	public boolean isValidEmail(String email) {
		
		return email.matches("^[a-zA-Z\\d_+&*-]+(?:\\.[a-zA-Z\\d_+&*-]+)*@(?:[a-zA-Z\\d-]+\\.)+[a-zA-Z]{2,7}$");
	}
	
	/**
	 * Validate a given credit card number using the Luhn algorithm.
	 * Input must have a remainder of 0 after sum is divided by 10.
	 *
	 * @param creditCard The credit card number to validate.
	 * @return True if it is a valid credit card number otherwise it returns false.
	 * @since 1.1.0
	 */
	public boolean isValidCreditCard(String creditCard) {
		
		String filteredCreditCard = creditCard.replaceAll(" ", "").trim();
		
		int evenSum = 0;
		int oddSum = 0;
		
		for (int i = filteredCreditCard.length() - 1; i >= 0; i--) {
			
			int n = Integer.parseInt(String.valueOf(filteredCreditCard.charAt(i)));
			
			if (isEven(i)) {
				
				n *= 2;
				
				if (n > 9) {
					
					String[] nString = String.valueOf(n).split("");
					
					for (String number : nString)
						
						evenSum += Integer.parseInt(number);
					
				} else {
					
					evenSum += n;
				}
				
			} else {
				
				oddSum += n;
			}
		}
		
		return (evenSum + oddSum) % 10 == 0;
	}
}
