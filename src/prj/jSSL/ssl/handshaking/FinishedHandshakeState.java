package prj.jSSL.ssl.handshaking;

import prj.jSSL.ssl.CustomSSLEngine;

public class FinishedHandshakeState extends IHandShakeState
{
    public FinishedHandshakeState(CustomSSLEngine sslEngine)
    {
        super(sslEngine);
    }

    @Override
    public void shakeHands()
    {
        finishHandshake();
    }
}
