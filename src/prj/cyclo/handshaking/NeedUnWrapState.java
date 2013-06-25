package prj.cyclo.handshaking;

import prj.cyclo.BufferAllocator;
import prj.cyclo.CryptoHelper;
import prj.cyclo.SSLManager;
import prj.cyclo.store.ISSLStore;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;

public class NeedUnWrapState<KEY> extends IHandShakeState<KEY>
{
    private KEY _userKey;
    public NeedUnWrapState(KEY userKey, ISSLStore<KEY> store)
    {
        super(store);
        _userKey = userKey;
    }

    @Override
    public boolean shakeHands() throws IOException
    {
        if (anyUnprocessedDataFromPreviousReceives(_userKey))
        {
            CryptoHelper<KEY> cryptoHelper = new CryptoHelper<KEY>(_store);
            ByteBuffer decryptedData = new BufferAllocator().allocateByteBuffer(getSSLEngine(_userKey), SSLManager.Operation.RECEIVING);
            SSLEngineResult unwrapResult = cryptoHelper.decrypt(_userKey, getSSLEngine(_userKey), new byte[0], decryptedData);
            if (unwrapResult.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP))
            {
                return true;
            }
            else if (isHandshakeStatusFinished(unwrapResult))
            {
                finishHandshake(_userKey); //go to finish state
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return true;
        }
    }

    private boolean anyUnprocessedDataFromPreviousReceives(KEY userKey)
    {
        byte[] bytes = _store.getRemainingData(userKey);
        return bytes!=null &&  bytes.length > 0;
    }
}
