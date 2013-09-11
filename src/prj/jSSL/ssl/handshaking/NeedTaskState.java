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
    public void shakeHands() throws IOException
    {
        processLongRunningTask();
    }

    private void processLongRunningTask()
    {
        Runnable task;
        while ((task = customSSLEngine.getSSLEngine().getDelegatedTask()) != null)
        {
            task.run();
        }
    }
}
