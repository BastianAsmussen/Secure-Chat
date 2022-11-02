package tech.asmussen.chat.util.printer;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

/**
 * <h1>FastPrinter</h1>
 *
 * <hr>
 *
 * <h2>Information:</h2>
 * <ul>
 *     <li>FastPrinter provides a fast way to print many elements to the terminal quickly.</li>
 *     <li>FastPrinter is thread-safe.</li>
 *     <li>It is faster than System.out.println() because it uses a buffer to store the output.</li>
 * </ul>
 *
 * </ul>
 * <h2>Usage:</h2>
 * <ul>
 *     <li>Create a new instance of FastPrinter using the {@link PrinterBuilder} class.</li>
 *     <li>Use the {@link #queue(Object)} method to add elements to the buffer.</li>
 *     <li>Use the {@link #flush()} method to print the buffer to the terminal.</li>
 * </ul>
 *
 * <hr>
 *
 * @author Bastian Asmussen
 * @version 1.0.0
 * @see #DEFAULT_CHARSET
 * @see #DEFAULT_BUFFER_SIZE
 * @see PrinterBuilder
 * @see #FastPrinter()
 * @see #FastPrinter(Charset, int)
 * @see #getCharset()
 * @see #getBuffer()
 * @see #getBufferSize()
 * @see #queue(Object)
 * @see #flush()
 * @see #println(Object...)
 */
public class FastPrinter {
	
	/**
	 * Used when no charset is specified.
	 *
	 * @see #FastPrinter()
	 * @see PrinterBuilder
	 * @since 1.0.0
	 */
	public static final Charset DEFAULT_CHARSET = StandardCharsets.US_ASCII;
	
	/**
	 * The default buffer size, it is used when no buffer size is specified.
	 *
	 * @see #FastPrinter()
	 * @see PrinterBuilder
	 * @since 1.0.0
	 */
	public static final int DEFAULT_BUFFER_SIZE = 16_384;
	
	/**
	 * The charset used to encode the output.
	 *
	 * @see #getCharset()
	 * @see #println(Object...)
	 */
	private final Charset charset;
	
	/**
	 * The buffer used to store the output.
	 *
	 * @see #getBuffer()
	 * @see #println(Object...)
	 */
	private final ArrayList<Object> buffer;
	
	/**
	 * The size of the buffer.
	 *
	 * @see #getBufferSize()
	 * @see #println(Object...)
	 */
	private final int bufferSize;
	
	/**
	 * Creates a new {@link FastPrinter} with the default charset and buffer size.
	 *
	 * @see #DEFAULT_CHARSET
	 * @see #DEFAULT_BUFFER_SIZE
	 * @see #FastPrinter(Charset, int)
	 * @since 1.0.0
	 */
	public FastPrinter() {
		
		this(DEFAULT_CHARSET, DEFAULT_BUFFER_SIZE);
	}
	
	/**
	 * Creates a new {@link FastPrinter} with the specified charset and buffer size.
	 * It is recommended that you use the {@link PrinterBuilder} to create a {@link FastPrinter}.
	 * It is also recommended that you use a buffer size that is between 64 and 1,048,576.
	 *
	 * @param charset    The charset used to encode the output.
	 * @param bufferSize The size of the buffer.
	 * @see PrinterBuilder
	 * @since 1.0.0
	 */
	public FastPrinter(Charset charset, int bufferSize) {
		
		this.charset = charset;
		this.bufferSize = bufferSize;
		
		buffer = new ArrayList<>();
	}
	
	/**
	 * Get the charset used to encode the output.
	 *
	 * @return The charset used to encode the output.
	 * @since 1.0.0
	 */
	public Charset getCharset() {
		
		return charset;
	}
	
	/**
	 * Get the buffer used to store the output.
	 *
	 * @return The buffer used to store the output.
	 * @since 1.0.0
	 */
	public int getBufferSize() {
		
		return bufferSize;
	}
	
	/**
	 * Get the size of the buffer.
	 *
	 * @return The size of the buffer.
	 * @since 1.0.0
	 */
	public Object[] getBuffer() {
		
		return buffer.toArray();
	}
	
	/**
	 * Queues the specified object to be printed.
	 *
	 * @param object The object to be printed.
	 * @since 1.0.0
	 */
	public void queue(Object object) {
		
		buffer.add(object);
		
		if (buffer.size() >= bufferSize) {
			
			flush();
		}
	}
	
	/**
	 * Flushes the buffer to the console.
	 *
	 * @since 1.0.0
	 */
	public void flush() {
		
		println(buffer.toArray());
		
		buffer.clear();
	}
	
	/**
	 * Prints the specified objects to the console.
	 *
	 * @param objects The objects to be printed.
	 * @see #charset
	 * @see #bufferSize
	 * @since 1.0.0
	 */
	private void println(Object... objects) {
		
		// Create a new BufferedWriter to write to the console, using the given charset and the given buffer size.
		BufferedWriter outputWriter = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(FileDescriptor.out), charset), bufferSize);
		
		try {
			
			for (Object object : objects) {
				
				outputWriter.write(object.toString()); // Write the string value of the object to the buffer.
				outputWriter.newLine(); // Write a new line to the buffer.
			}
			
			outputWriter.flush(); // Flush the buffer to the console.
			
		} catch (IOException e) {
			
			e.printStackTrace();
		}
	}
}
