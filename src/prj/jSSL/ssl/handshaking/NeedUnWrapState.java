package prj.jSSL.ssl.handshaking;

import prj.jSSL.BufferAllocator;
import prj.jSSL.CryptoHelper;
import prj.jSSL.SSLManager;
import prj.jSSL.ssl.CustomSSLEngine;
import prj.jSSL.ssl.IReaderWriter;
import prj.jSSL.store.ISSLStore;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;

public class NeedUnWrapState extends IHandShakeState
{
    public NeedUnWrapState(CustomSSLEngine _sslEngine)
    {
        super(_sslEngine);
    }

    @Override
    public boolean shakeHands() throws IOException
    {
        if (anyUnprocessedDataFromPreviousReceives())
        {
            CryptoHelper cryptoHelper = new CryptoHelper();
            ByteBuffer decryptedData = new BufferAllocator().allocateByteBuffer(_sslEngine, SSLManager.Operation.RECEIVING);
            SSLEngineResult unwrapResult = cryptoHelper.decrypt(_sslEngine, new byte[0], decryptedData);
            if (unwrapResult.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP))
            {
                return true;
            }
            else if (isHandshakeStatusFinished(unwrapResult))
            {
                finishHandshake(); //go to finish state
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

    private boolean anyUnprocessedDataFromPreviousReceives()
    {
        String data = _sslEngine.read(IReaderWriter.ReadEvent.REMAINING_DATA);
        return data!=null &&  !data.isEmpty();
    }
}
