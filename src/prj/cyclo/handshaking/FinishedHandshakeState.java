package prj.cyclo.handshaking;

import prj.cyclo.store.ISSLStore;

public class FinishedHandshakeState<KEY> extends IHandShakeState<KEY>
{
    private KEY _userKey;

    public FinishedHandshakeState(KEY userKey, ISSLStore<KEY> store)
    {
        super(store);
        _userKey = userKey;
    }

    @Override
    public boolean shakeHands()
    {
        finishHandshake(_userKey);
        return true;
    }
}
