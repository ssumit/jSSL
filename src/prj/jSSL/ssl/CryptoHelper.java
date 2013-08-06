package prj.jSSL.ssl;

import org.slf4j.LoggerFactory;
import prj.jSSL.SSLManager;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * This class contains convenience extensions f SSL Engine's wrap and unwrap methods. SSL Engine consumes complete
 * TLS/SSL packets only, therefore we might need to handle buffer underflow cae of unwrap method. Rest all cases can be
 * handled by taking th buffer of appropriate sizes.
 */

public class CryptoHelper
{
    private org.slf4j.Logger _logger = LoggerFactory.getLogger(CryptoHelper.this.getClass().getSimpleName());

    public void decrypt(CustomSSLEngine sslEngine, byte[] encryptedDataBytes) throws IOException
    {
        try
        {
            unwrap(sslEngine, encryptedDataBytes);
        }
        catch (IOException exception)
        {
            _logger.info("ssl exception while decrypting data: {} {}", new String(encryptedDataBytes), exception);
            throw exception;
        }
    }

    public void encrypt(CustomSSLEngine customSSLEngine, byte[] data) throws IOException
    {
        wrap(customSSLEngine, data);
    }

    private SSLEngineResult wrap(CustomSSLEngine customSSLEngine, byte[] plainAppData) throws IOException
    {
        ByteBuffer applicationData = ByteBuffer.allocate(plainAppData.length);
        ByteBuffer outgoingData = new BufferAllocator().getEmptyByteBuffer(customSSLEngine, SSLManager.Operation.SENDING);
        while (true)
        {
            SSLEngineResult sslEngineResult = customSSLEngine.getSSLEngine().wrap(applicationData, outgoingData);
            switch (sslEngineResult.getStatus())
            {
                case BUFFER_UNDERFLOW:
                    //source buffer is small so either we enlarge it or break the data to call wrap multiple time it
                    throw new RuntimeException("BUFFER UNDERFLOW WRAP");
                case BUFFER_OVERFLOW:
                    //break the data into smaller chunks as the destination buffer is small and again wrap OR we can enlarge the buffer
                    int appSize = customSSLEngine.getSSLEngine().getSession().getPacketBufferSize();
                    ByteBuffer byteBuffer = ByteBuffer.allocate(appSize + outgoingData.position());
                    outgoingData.flip();
                    byteBuffer.put(outgoingData);
                    outgoingData = byteBuffer;
                    break;
                case OK:
                    customSSLEngine.write(IReaderWriter.WriteEvent.WRAPPED_OUTPUT, outgoingData.array());
                    return sslEngineResult;
                case CLOSED:
                    break;
            }
        }
    }

    private SSLEngineResult unwrap(CustomSSLEngine customSSLEngine, byte[] encryptedDataBytes) throws IOException, RuntimeException
    {
        byte[] pendingData = customSSLEngine.read(IReaderWriter.ReadEvent.REMAINING_UNPROCESSED_DATA);
        ByteBuffer totalIncomingData = ByteBuffer.allocate(pendingData.length + encryptedDataBytes.length);
        totalIncomingData.put(pendingData);
        totalIncomingData.put(encryptedDataBytes);
        ByteBuffer unwrappedData = new BufferAllocator().getEmptyByteBuffer(customSSLEngine, SSLManager.Operation.RECEIVING);
        while (true)
        {
            SSLEngineResult result = customSSLEngine.getSSLEngine().unwrap(totalIncomingData, unwrappedData);
            switch (result.getStatus())
            {
                case BUFFER_UNDERFLOW:
                    //source buffer is small so we enlarge it. Also we might have to  wait till a complete TLS/SSL packet arrives as SSL Engine does not work on partial packets.
                    customSSLEngine.write(IReaderWriter.WriteEvent.REMAINING_UNPROCESSED_DATA, encryptedDataBytes);
                case BUFFER_OVERFLOW:
                    //break the data into smaller chunks as the destination buffer is small and again unwrap OR we can enlarge the buffer
                    int appSize = customSSLEngine.getSSLEngine().getSession().getApplicationBufferSize();
                    ByteBuffer byteBuffer = ByteBuffer.allocate(appSize + unwrappedData.position());
                    unwrappedData.flip();
                    byteBuffer.put(unwrappedData);
                    unwrappedData = byteBuffer;
                    break;
                case OK:
                    customSSLEngine.write(IReaderWriter.WriteEvent.UNWRAPPED_OUTPUT, unwrappedData.array());
                    return result;
                case CLOSED:
                        break;
            }
        }
    }
}
