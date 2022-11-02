package tech.asmussen.chat.util.printer;

import java.nio.charset.Charset;

/**
 * Build a {@link FastPrinter} instance.
 *
 * @author Bastian Asmussen
 * @version 1.0.0
 * @see #PrinterBuilder()
 * @see #setCharset(Charset)
 * @see #setBufferSize(int)
 * @see #estimateBufferSize(int)
 * @see #getCharset()
 * @see #getBufferSize()
 * @see #build()
 */
public class PrinterBuilder {
	
	/**
	 * The charset used to encode the output.
	 *
	 * @see #setCharset(Charset)
	 * @see #build()
	 */
	private Charset charset;
	
	/**
	 * The buffer size used to store the output.
	 *
	 * @see #setBufferSize(int)
	 * @see #build()
	 */
	private int bufferSize;
	
	/**
	 * Create a new {@link PrinterBuilder} instance.
	 *
	 * @see FastPrinter#DEFAULT_CHARSET
	 * @see FastPrinter#DEFAULT_BUFFER_SIZE
	 * @see #setCharset(Charset)
	 * @see #setBufferSize(int)
	 * @see #build()
	 * @since 1.0.0
	 */
	public PrinterBuilder() {
		
		this.charset = FastPrinter.DEFAULT_CHARSET;
		this.bufferSize = FastPrinter.DEFAULT_BUFFER_SIZE;
	}
	
	/**
	 * Get the charset used by this {@link PrinterBuilder} instance.
	 *
	 * @return The charset used.
	 * @see #charset
	 * @since 1.0.0
	 */
	public Charset getCharset() {
		
		return charset;
	}
	
	/**
	 * Set the charset used to encode the output.
	 * It is recommended that you use a buffer size that is between 64 and 1,048,576.
	 *
	 * @param charset The charset used to encode the output.
	 * @return This {@link PrinterBuilder} instance.
	 * @see #charset
	 * @see #build()
	 * @since 1.0.0
	 */
	public PrinterBuilder setCharset(Charset charset) {
		
		this.charset = charset;
		
		return this;
	}
	
	/**
	 * Get the buffer size used by this {@link PrinterBuilder} instance.
	 *
	 * @return The buffer size used.
	 * @see #bufferSize
	 * @since 1.0.0
	 */
	public int getBufferSize() {
		
		return bufferSize;
	}
	
	/**
	 * Set the buffer size used to store the output.
	 *
	 * @param bufferSize The buffer size used to store the output.
	 * @return This {@link PrinterBuilder} instance.
	 * @see #bufferSize
	 * @see #build()
	 * @since 1.0.0
	 */
	public PrinterBuilder setBufferSize(int bufferSize) {
		
		this.bufferSize = bufferSize;
		
		return this;
	}
	
	/**
	 * Based on how many elements you think you'll be printing, this method will calculate the buffer size.
	 *
	 * @param elementCount The number of elements you think you'll be printing.
	 * @see #bufferSize
	 * @see #setBufferSize(int)
	 * @see #build()
	 * @since 1.0.0
	 */
	public PrinterBuilder estimateBufferSize(int elementCount) {
		
		bufferSize = elementCount * 2;
		
		return this;
	}
	
	/**
	 * Build a new {@link FastPrinter} instance.
	 *
	 * @return A new {@link FastPrinter} instance.
	 * @see #charset
	 * @see #bufferSize
	 * @since 1.0.0
	 */
	public FastPrinter build() {
		
		return new FastPrinter(charset, bufferSize);
	}
}
