package prj.jSSL.ssl;

import org.slf4j.LoggerFactory;
import prj.jSSL.SSLManager;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;

public class CryptoHelper
{
    private org.slf4j.Logger _logger = LoggerFactory.getLogger(CryptoHelper.this.getClass().getSimpleName());

    public SSLEngineResult decrypt(CustomSSLEngine sslEngine, byte[] encryptedDataBytes) throws IOException
    {
        try
        {
            SSLEngineResult result = unwrap(sslEngine, encryptedDataBytes);
            if (isHandshakeStatusFinished(result))
            {
                new SSLShakehandsHandler(sslEngine).finishShakeHand();
            }
            return result;
        }
        catch (IOException exception)
        {
            _logger.info("ssl exception while decrypting data: {} {}", new String(encryptedDataBytes), exception);
            throw exception;
        }
    }

    public SSLEngineResult encrypt(CustomSSLEngine customSSLEngine, byte[] data, ByteBuffer outgoingData) throws IOException
    {
        ByteBuffer applicationData = ByteBuffer.wrap(data);
        return customSSLEngine.getSSLEngine().wrap(applicationData, outgoingData);
    }

    /**
     *
     * @param customSSLEngine
     * @return
     * @throws IOException
     * @throws RuntimeException
     * This function requires some minimum amount of data(say some required number of bytes) to work on. If the amount of data is less then this data needs to be stored.
     * This function will read the pending data along with new data do unwrap and store any remaining data if required.
     */
    private SSLEngineResult unwrap(CustomSSLEngine customSSLEngine, byte[] encryptedDataBytes) throws IOException, RuntimeException
    {
        byte[] pendingData = customSSLEngine.read(IReaderWriter.ReadEvent.REMAINING_DATA);
        ByteBuffer totalIncomingData = ByteBuffer.allocate(pendingData.length + encryptedDataBytes.length);
        totalIncomingData.put(pendingData);
        totalIncomingData.put(encryptedDataBytes);
        ByteBuffer unwrappedData = new BufferAllocator().getEmptyByteBuffer(customSSLEngine, SSLManager.Operation.RECEIVING);
        int totalBytesConsumed = 0;
        int totalBytesToBeConsumed = totalIncomingData.array().length;
        while (true)
        {
            SSLEngineResult result = customSSLEngine.getSSLEngine().unwrap(totalIncomingData, unwrappedData);
            totalBytesConsumed = totalBytesConsumed + result.bytesConsumed();
            switch (result.getStatus())
            {
                case BUFFER_UNDERFLOW:
                    int netSize = customSSLEngine.getSSLEngine().getSession().getPacketBufferSize();
                    if(netSize > unwrappedData.capacity())
                    {
                        ByteBuffer byteBuffer = ByteBuffer.allocate(netSize);
                        totalIncomingData.flip();
                        byteBuffer.put(totalIncomingData);
                        totalIncomingData = byteBuffer;
                    }
                    else
                    {
                        throw new RuntimeException("packet is not completely received.. cannot process will store data");
                    }
                    break;
                case BUFFER_OVERFLOW:
                    int appSize = customSSLEngine.getSSLEngine().getSession().getApplicationBufferSize();
                    ByteBuffer byteBuffer = ByteBuffer.allocate(appSize + unwrappedData.position());
                    unwrappedData.flip();
                    byteBuffer.put(unwrappedData);
                    unwrappedData = byteBuffer;
                    break;
                case OK:
                    SSLEngineResult.HandshakeStatus handshakeStatus = customSSLEngine.getSSLEngine().getHandshakeStatus();
                    if(handshakeStatus.equals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP) && result.bytesProduced() == 0)
                    {
                        continue;
                        //repeat;
                    }
                    else if(handshakeStatus.equals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) && (result.bytesProduced()!= 0 || totalBytesConsumed < totalBytesToBeConsumed))
                    {
                        continue;
                        //repeat;
                    }
                    else
                    {
                        //do not repeat
                        return result;
                    }
                case CLOSED:
                        break;
            }
        }
    }

    protected boolean isHandshakeStatusFinished(SSLEngineResult result)
    {
        return result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.FINISHED);
    }
}
