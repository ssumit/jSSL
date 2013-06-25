package prj.cyclo;

import org.slf4j.LoggerFactory;
import prj.cyclo.store.ISSLStore;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class CryptoHelper<KEY>
{
    private ISSLStore<KEY> _store;
    private org.slf4j.Logger _logger = LoggerFactory.getLogger(CryptoHelper.this.getClass().getSimpleName());

    public CryptoHelper(ISSLStore<KEY> _store)
    {
        this._store = _store;
    }

    public SSLEngineResult decrypt(KEY userKey, SSLEngine sslEngine, byte[] incomingBytes, ByteBuffer decryptedData) throws IOException
    {
        ByteBuffer encryptedData = getDataForDecryption(userKey, incomingBytes);
        try
        {
            SSLEngineResult result = unwrap(userKey, sslEngine, decryptedData, encryptedData);
            storeUnprocessedData(userKey, encryptedData);
            if (isHandshakeStatusFinished(result))
            {
                new SSLShakehandsHandler(userKey, _store).finishShakeHand(userKey);
            }
            return result;
        }
        catch (IOException exception)
        {
            _logger.info("ssl exception while decrypting data: {} {}", new String(incomingBytes), exception);
            throw exception;
        }
    }

    public SSLEngineResult encrypt(SSLEngine sslEngine, byte[] data, ByteBuffer outgoingData) throws IOException
    {
        ByteBuffer applicationData = ByteBuffer.wrap(data);
        return sslEngine.wrap(applicationData, outgoingData);
    }

    private ByteBuffer getDataForDecryption(KEY userKey, byte[] encryptedData)
    {
        byte[] remainingData =_store.getRemainingData(userKey);
        int length_remainingData = remainingData.length;
        int length_encryptedData = encryptedData.length;
        ByteBuffer totalIncomingData = ByteBuffer.allocate(length_remainingData + length_encryptedData);

        addPendingData(userKey, remainingData, totalIncomingData);
        addLatestData(encryptedData, totalIncomingData);

        totalIncomingData.flip();
        return totalIncomingData;
    }

    private SSLEngineResult unwrap(KEY key, SSLEngine sslEngine, ByteBuffer unwrappedData, ByteBuffer totalIncomingData) throws IOException
    {
        SSLEngineResult result;
        int totalBytesConsumed = 0;
        int totalBytesToBeConsumed = totalIncomingData.array().length;
        do
        {
            result = sslEngine.unwrap(totalIncomingData, unwrappedData);
            totalBytesConsumed = totalBytesConsumed + result.bytesConsumed();
        }
        while (needsUnwrap(key, result, totalBytesConsumed, totalBytesToBeConsumed));
        return result;
    }

    private void storeUnprocessedData(KEY userKey, ByteBuffer totalIncomingData)
    {
        byte[] remainingData = Arrays.copyOfRange(totalIncomingData.array(), totalIncomingData.position(), totalIncomingData.limit());
        _store.putRemainingData(userKey, remainingData);
    }

    protected boolean isHandshakeStatusFinished(SSLEngineResult result)
    {
        return result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.FINISHED);
    }

    private boolean needsUnwrap(KEY key, SSLEngineResult result, int totalBytesConsumed, int totalBytesToBeConsumed)
    {
        if (!isHandshakeCompleted(key))
        {
            return result.getStatus() == SSLEngineResult.Status.OK && result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP) && result.bytesProduced() == 0;
        }
        else
        {
            return result.getStatus() == SSLEngineResult.Status.OK && (result.bytesProduced() != 0 || totalBytesConsumed < totalBytesToBeConsumed);
        }
    }

    private static void addLatestData(byte[] encryptedData, ByteBuffer totalIncomingData)
    {
        if (encryptedData.length > 0)
        {
            totalIncomingData.put(encryptedData);
        }
    }

    private void addPendingData(KEY userKey, byte[] remainingData, ByteBuffer totalIncomingData)
    {
        if (remainingData.length > 0)
        {
            totalIncomingData.put(remainingData);
            _store.putRemainingData(userKey, new byte[0]);
        }
    }

    private boolean isHandshakeCompleted(KEY userKey)
    {
        return _store.getHandShakeCompletedStatus(userKey);
    }
}
