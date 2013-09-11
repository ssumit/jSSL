package prj.jSSL.ssl.handshaking;

import org.slf4j.LoggerFactory;
import prj.jSSL.ssl.CustomSSLEngine;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;

public class SSLHandshakeStateHolder
{
    private IHandShakeState _handShakeState;
    private CustomSSLEngine customSSLEngine;
    private org.slf4j.Logger _logger = LoggerFactory.getLogger(SSLHandshakeStateHolder.this.getClass().getSimpleName());

    public SSLHandshakeStateHolder(SSLEngineResult.HandshakeStatus handshakeStatus, CustomSSLEngine sslEngine)
    {
        customSSLEngine = sslEngine;
        _handShakeState = getAppropriateState(handshakeStatus, customSSLEngine);
    }

    public SSLHandshakeStateHolder(CustomSSLEngine customSSLEngine)
    {
        this(customSSLEngine.getHandshakeStatus(), customSSLEngine);
    }

    public boolean shakeHands() throws IOException
    {
        boolean returnVal = _handShakeState.shakeHands();
        _handShakeState = getAppropriateState(customSSLEngine.getHandshakeStatus(), customSSLEngine);
        return returnVal;
    }

    private IHandShakeState getAppropriateState(SSLEngineResult.HandshakeStatus handshakeStatus, CustomSSLEngine sslEngine) {
        System.out.println("hand shake holder state : " + handshakeStatus.name());
        switch (handshakeStatus)
        {
            case FINISHED:
                return new FinishedHandshakeState(sslEngine);
            case NOT_HANDSHAKING:
                return new NotHandShakingState(sslEngine);
            case NEED_TASK:
                return new NeedTaskState(sslEngine);
            case NEED_WRAP:
                return new NeedWrapState(sslEngine);
            case NEED_UNWRAP:
                return new NeedUnWrapState(sslEngine);
            default:
                return new IHandShakeState(sslEngine) {
                    @Override
                    public boolean shakeHands() {
                        _logger.warn("Illegal Handshake status");
                        return true;
                    }
                };
        }
    }
}
