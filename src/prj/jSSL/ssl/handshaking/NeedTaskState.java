package prj.jSSL.ssl.handshaking;

import prj.jSSL.ssl.CustomSSLEngine;

import java.io.IOException;

public class NeedTaskState extends IHandShakeState
{
    public NeedTaskState(CustomSSLEngine sslEngine)
    {
        super(sslEngine);
    }

    @Override
    public boolean shakeHands() throws IOException
    {
        processLongRunningTask();
        return false;
    }

    private void processLongRunningTask()
    {
        Runnable task;
        while ((task = _sslEngine.getDelegatedTask()) != null)
        {
            task.run();
        }
    }
}
