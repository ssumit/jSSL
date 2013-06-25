package prj.cyclo.handshaking;

import org.slf4j.LoggerFactory;
import prj.cyclo.SSLTransport;
import prj.cyclo.store.ISSLStore;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;

public class SSLHandshakeStateHolder<KEY>
{
    private IHandShakeState _handShakeState;
    private KEY _userKey;
    private ISSLStore<KEY> _store;
    private SSLTransport<KEY> _transport;
    private org.slf4j.Logger _logger = LoggerFactory.getLogger(SSLHandshakeStateHolder.this.getClass().getSimpleName());

    public SSLHandshakeStateHolder(SSLEngineResult.HandshakeStatus handshakeStatus, KEY userKey, ISSLStore<KEY> store, SSLTransport<KEY> transport)
    {
        _userKey = userKey;
        _store = store;
        _transport = transport;
        _handShakeState = getAppropriateState(handshakeStatus);
    }

    public boolean shakeHands() throws IOException
    {
        return _handShakeState.shakeHands();
    }

    private IHandShakeState getAppropriateState(SSLEngineResult.HandshakeStatus handshakeStatus) {
        switch (handshakeStatus)
        {
            case FINISHED:
                return new FinishedHandshakeState(_userKey, _store);
            case NOT_HANDSHAKING:
                return new NotHandShakingState(_store);
            case NEED_TASK:
                return new NeedTaskState(_userKey, _store);
            case NEED_WRAP:
                return new NeedWrapState(_userKey, _store, _transport);
            case NEED_UNWRAP:
                return new NeedUnWrapState(_userKey, _store);
            default:
                return new IHandShakeState(_store) {
                    @Override
                    public boolean shakeHands() {
                        _logger.warn("Illegal Handshake status");
                        return true;
                    }
                };
        }
    }
}
