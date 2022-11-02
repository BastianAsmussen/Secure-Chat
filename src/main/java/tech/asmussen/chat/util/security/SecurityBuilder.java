package tech.asmussen.chat.util.security;

import java.security.PublicKey;

/**
 * This class is used to build a {@link Security} object.
 *
 * @author Bastian Asmussen
 * @version 1.0.0
 * @see #setKeySize(int)
 * @see #setKeyPairAlgorithm(String)
 * @see #setPublicKeyDelimiters(String[])
 * @see #setCipherAlgorithm(String)
 * @see #setCPUCost(int)
 * @see #setMemoryCost(int)
 * @see #setParallelization(int)
 * @see #setValidationURL(String)
 * @see #build()
 */
public class SecurityBuilder {
	
	private int keySize;
	
	private String keyPairAlgorithm;
	private String[] publicKeyDelimiters;
	
	private String cipherAlgorithm;
	
	private int cpuCost;
	private int memoryCost;
	private int parallelization;
	
	private String validationURL;
	
	/**
	 * Creates a new {@link SecurityBuilder} object with default values.
	 *
	 * @see Security#DEFAULT_KEY_SIZE
	 * @see Security#DEFAULT_KEY_PAIR_ALGORITHM
	 * @see Security#DEFAULT_PUBLIC_KEY_DELIMITERS
	 * @see Security#DEFAULT_CIPHER_ALGORITHM
	 * @see Security#DEFAULT_CPU_COST
	 * @see Security#DEFAULT_MEMORY_COST
	 * @see Security#DEFAULT_PARALLELIZATION
	 * @see Security#DEFAULT_VALIDATION_URL
	 * @since 1.0.0
	 */
	public SecurityBuilder() {
		
		this.keySize = Security.DEFAULT_KEY_SIZE;
		this.keyPairAlgorithm = Security.DEFAULT_KEY_PAIR_ALGORITHM;
		this.publicKeyDelimiters = Security.DEFAULT_PUBLIC_KEY_DELIMITERS;
		
		this.cipherAlgorithm = Security.DEFAULT_CIPHER_ALGORITHM;
		
		this.cpuCost = Security.DEFAULT_CPU_COST;
		this.memoryCost = Security.DEFAULT_MEMORY_COST;
		this.parallelization = Security.DEFAULT_PARALLELIZATION;
		
		this.validationURL = Security.DEFAULT_VALIDATION_URL;
	}
	
	/**
	 * Sets the key size to use.
	 *
	 * @param keySize The key size.
	 * @return This {@link SecurityBuilder} object.
	 * @since 1.0.0
	 */
	public SecurityBuilder setKeySize(int keySize) {
		
		this.keySize = keySize;
		
		return this;
	}
	
	/**
	 * Sets the key pair algorithm to use.
	 *
	 * @param keyPairAlgorithm The key pair algorithm.
	 * @return This {@link SecurityBuilder} object.
	 * @since 1.0.0
	 */
	public SecurityBuilder setKeyPairAlgorithm(String keyPairAlgorithm) {
		
		this.keyPairAlgorithm = keyPairAlgorithm;
		
		return this;
	}
	
	/**
	 * Sets the delimiters to use when converting a {@link PublicKey} to a {@link String}.
	 *
	 * @param publicKeyDelimiters The delimiters.
	 * @return This {@link SecurityBuilder} object.
	 * @since 1.0.0
	 */
	public SecurityBuilder setPublicKeyDelimiters(String[] publicKeyDelimiters) {
		
		this.publicKeyDelimiters = publicKeyDelimiters;
		
		return this;
	}
	
	/**
	 * Sets the cipher algorithm to use.
	 *
	 * @param cipherAlgorithm The cipher algorithm.
	 * @return This {@link SecurityBuilder} object.
	 * @since 1.0.0
	 */
	public SecurityBuilder setCipherAlgorithm(String cipherAlgorithm) {
		
		this.cipherAlgorithm = cipherAlgorithm;
		
		return this;
	}
	
	/**
	 * Sets the cpu cost to use.
	 *
	 * @param cpuCost The cpu cost.
	 * @return This {@link SecurityBuilder} object.
	 * @since 1.0.0
	 */
	public SecurityBuilder setCPUCost(int cpuCost) {
		
		this.cpuCost = cpuCost;
		
		return this;
	}
	
	/**
	 * Sets the memory cost to use.
	 *
	 * @param memoryCost The memory cost.
	 * @return This {@link SecurityBuilder} object.
	 * @since 1.0.0
	 */
	public SecurityBuilder setMemoryCost(int memoryCost) {
		
		this.memoryCost = memoryCost;
		
		return this;
	}
	
	/**
	 * Sets the parallelization to use.
	 *
	 * @param parallelization The parallelization.
	 * @return This {@link SecurityBuilder} object.
	 * @since 1.0.0
	 */
	public SecurityBuilder setParallelization(int parallelization) {
		
		this.parallelization = parallelization;
		
		return this;
	}
	
	/**
	 * Sets the validation URL to use.
	 *
	 * @param validationURL The validation URL.
	 * @return This {@link SecurityBuilder} object.
	 * @since 1.0.0
	 */
	public SecurityBuilder setValidationURL(String validationURL) {
		
		this.validationURL = validationURL;
		
		return this;
	}
	
	/**
	 * Builds a {@link Security} object with the given parameters.
	 *
	 * @return The {@link Security} object.
	 * @see Security#Security(int, String, String[], String, int, int, int, String)
	 * @since 1.0.0
	 */
	public Security build() {
		
		return new Security(keySize, keyPairAlgorithm, publicKeyDelimiters, cipherAlgorithm, cpuCost, memoryCost, parallelization, validationURL);
	}
}
