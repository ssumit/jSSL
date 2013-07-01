package prj.jSSL.ssl.handshaking;

import prj.jSSL.ssl.CustomSSLEngine;

public class NotHandShakingState<KEY> extends IHandShakeState
{
    public NotHandShakingState(CustomSSLEngine sslEngine)
    {
        super(sslEngine);
    }

    @Override
    public boolean shakeHands()
    {
        return true;
    }
}
