package prj.cyclo.handshaking;

import prj.cyclo.store.ISSLStore;

public class NotHandShakingState<KEY> extends IHandShakeState<KEY>
{
    public NotHandShakingState(ISSLStore<KEY> store)
    {
        super(store);
    }

    @Override
    public boolean shakeHands()
    {
        return true;
    }
}
