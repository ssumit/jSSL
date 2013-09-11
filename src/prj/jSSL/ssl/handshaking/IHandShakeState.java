package prj.jSSL.ssl.handshaking;

import prj.jSSL.ssl.CustomSSLEngine;
import prj.jSSL.ssl.IReaderWriter;

import java.io.IOException;

public abstract class IHandShakeState
{
    protected CustomSSLEngine customSSLEngine;

    public IHandShakeState(CustomSSLEngine sslEngine)
    {
        customSSLEngine = sslEngine;
    }

    public abstract void shakeHands() throws IOException;

    protected void finishHandshake()
    {
        customSSLEngine.write(IReaderWriter.WriteEvent.HANDSHAKE_COMPLETE_STATUS, String.valueOf(true).getBytes());
    }
}
