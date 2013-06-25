package prj.cyclo.handshaking;

import prj.cyclo.store.ISSLStore;

import javax.net.ssl.SSLEngine;
import java.io.IOException;

public class NeedTaskState<KEY> extends IHandShakeState<KEY>
{
    private KEY _userKey;

    public NeedTaskState(KEY userKey, ISSLStore<KEY> _store)
    {
        super(_store);
        _userKey = userKey;
    }

    @Override
    public boolean shakeHands() throws IOException
    {
        SSLEngine sslEngine = getSSLEngine(_userKey);
        processLongRunningTask(sslEngine);
        return false;
    }

    private void processLongRunningTask(SSLEngine sslEngine)
    {
        Runnable task;
        while ((task = sslEngine.getDelegatedTask()) != null)
        {
            task.run();
        }
    }
}
