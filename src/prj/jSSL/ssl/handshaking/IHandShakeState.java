package prj.jSSL.ssl.handshaking;

import prj.jSSL.ssl.CustomSSLEngine;
import prj.jSSL.ssl.IReaderWriter;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;

public abstract class IHandShakeState
{
    protected CustomSSLEngine _sslEngine;

    public IHandShakeState(CustomSSLEngine sslEngine)
    {
        _sslEngine = sslEngine;
    }

    public abstract boolean shakeHands() throws IOException;

    protected void finishHandshake()
    {
        _sslEngine.write(IReaderWriter.WriteEvent.HANDSHAKE_COMPLETE_STATUS, String.valueOf(true));
    }

    protected boolean isHandshakeStatusFinished(SSLEngineResult result)
    {
        return result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.FINISHED);
    }
}
