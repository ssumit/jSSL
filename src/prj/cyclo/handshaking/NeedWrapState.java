package prj.cyclo.handshaking;

import prj.cyclo.BufferAllocator;
import prj.cyclo.CryptoHelper;
import prj.cyclo.SSLManager;
import prj.cyclo.SSLTransport;
import prj.cyclo.store.ISSLStore;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;

public class NeedWrapState<KEY> extends IHandShakeState<KEY>
{
    private KEY _userKey;
    private SSLTransport<KEY> _transport;

    public NeedWrapState(KEY userKey, ISSLStore<KEY> store, SSLTransport<KEY> transport)
    {
        super(store);
        _userKey = userKey;
        _transport = transport;
    }

    @Override
    public boolean shakeHands() throws IOException
    {
        SSLEngineResult result = wrapAndSend(_userKey);
        if (isHandshakeStatusFinished(result))
        {
            finishHandshake(_userKey); //we will go to finish state
            return true;
        }
        else
        {
            return false;
        }
    }

    private SSLEngineResult wrapAndSend(KEY userKey) throws IOException
    {
        ByteBuffer encryptedData = new BufferAllocator().allocateByteBuffer(getSSLEngine(userKey), SSLManager.Operation.SENDING);
        SSLEngineResult result = new CryptoHelper<KEY>(_store).encrypt(getSSLEngine(userKey), new byte[0], encryptedData);
        encryptedData.flip();

        byte[] sslMessage = getSSLMessageBytesFromBuffer(encryptedData, result);
        _transport.send(userKey, sslMessage);
        return result;
    }

    private byte[] getSSLMessageBytesFromBuffer(ByteBuffer encryptedData, SSLEngineResult result)
    {
        byte[] sslMessage = new byte[result.bytesProduced()];
        encryptedData.get(sslMessage, 0, result.bytesProduced());
        return sslMessage;
    }
}
