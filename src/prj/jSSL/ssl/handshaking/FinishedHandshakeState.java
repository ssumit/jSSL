package prj.jSSL.ssl.handshaking;

import prj.jSSL.ssl.CustomSSLEngine;

public class FinishedHandshakeState<KEY> extends IHandShakeState
{
    public FinishedHandshakeState(CustomSSLEngine sslEngine)
    {
        super(sslEngine);
    }

    @Override
    public boolean shakeHands()
    {
        finishHandshake();
        return true;
    }
}
