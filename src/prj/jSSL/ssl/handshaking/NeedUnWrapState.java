package prj.jSSL.ssl.handshaking;

import prj.jSSL.ssl.CryptoHelper;
import prj.jSSL.ssl.CustomSSLEngine;
import prj.jSSL.ssl.IReaderWriter;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;

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
            SSLEngineResult unwrapResult = cryptoHelper.decrypt(customSSLEngine, new byte[0]);
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
        byte[] data = customSSLEngine.read(IReaderWriter.ReadEvent.REMAINING_DATA);
        return data!=null &&  data.length>0;
    }
}
