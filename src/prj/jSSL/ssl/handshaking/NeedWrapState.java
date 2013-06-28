package prj.jSSL.ssl.handshaking;

import prj.jSSL.BufferAllocator;
import prj.jSSL.CryptoHelper;
import prj.jSSL.SSLManager;
import prj.jSSL.ssl.CustomSSLEngine;
import prj.jSSL.ssl.IReaderWriter;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;

public class NeedWrapState extends IHandShakeState
{
    public NeedWrapState(CustomSSLEngine sslEngine)
    {
        super(sslEngine);
    }

    @Override
    public boolean shakeHands() throws IOException
    {
        SSLEngineResult result = wrapAndSend();
        if (isHandshakeStatusFinished(result))
        {
            finishHandshake(); //we will go to finish state
            return true;
        }
        else
        {
            return false;
        }
    }

    private SSLEngineResult wrapAndSend() throws IOException
    {
        ByteBuffer encryptedData = new BufferAllocator().allocateByteBuffer(_sslEngine, SSLManager.Operation.SENDING);
        SSLEngineResult result = new CryptoHelper().encrypt(_sslEngine, new byte[0], encryptedData);
        encryptedData.flip();

        byte[] sslMessage = getSSLMessageBytesFromBuffer(encryptedData, result);
        _sslEngine.write(IReaderWriter.WriteEvent.WRAP_STATE, sslMessage.toString());
        return result;
    }

    private byte[] getSSLMessageBytesFromBuffer(ByteBuffer encryptedData, SSLEngineResult result)
    {
        byte[] sslMessage = new byte[result.bytesProduced()];
        encryptedData.get(sslMessage, 0, result.bytesProduced());
        return sslMessage;
    }
}
