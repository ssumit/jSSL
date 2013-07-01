package prj.jSSL.ssl.handshaking;

import prj.jSSL.ssl.CustomSSLEngine;
import prj.jSSL.ssl.IReaderWriter;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;

public abstract class IHandShakeState
{
    protected CustomSSLEngine customSSLEngine;

    public IHandShakeState(CustomSSLEngine sslEngine)
    {
        customSSLEngine = sslEngine;
    }

    public abstract boolean shakeHands() throws IOException;

    protected void finishHandshake()
    {
        customSSLEngine.write(IReaderWriter.WriteEvent.HANDSHAKE_COMPLETE_STATUS, String.valueOf(true));
    }

    protected boolean isHandshakeStatusFinished(SSLEngineResult result)
    {
        return result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.FINISHED);
    }
}
