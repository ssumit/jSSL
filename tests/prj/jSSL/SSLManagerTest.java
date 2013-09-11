package prj.jSSL;

import org.junit.Before;
import org.junit.Test;
import prj.jSSL.ssl.IReaderWriter;
import prj.jSSL.store.KeyStoreInfo;
import prj.jSSL.store.SSLStore;

import java.io.IOException;

import static junit.framework.Assert.assertTrue;

public class SSLManagerTest
{
    private SSLManager<Integer> sslServer;
    private SSLManager<Integer> sslClient;

    @Before
    public void init()
    {
        String keyValueStoreName = "cyclekeystore";
        String keyValueStoreType = "JKS";
        String keyValueStorePassword = "qwerty";
        String keyValueStoreProtocol= "TLS";
        KeyStoreInfo keyStoreInfo = new KeyStoreInfo(keyValueStoreName, keyValueStoreType, keyValueStorePassword, keyValueStoreProtocol);
        Config serverConfig = new Config();
        serverConfig.setClientMode(false);
        serverConfig.setKeyStoreInfo(keyStoreInfo);
        Config clientConfig = new Config();
        clientConfig.setClientMode(true);
        clientConfig.setKeyStoreInfo(keyStoreInfo);
        sslServer = new SSLManager<>(new SSLStore<Integer>(), serverConfig);
        sslClient = new SSLManager<>(new SSLStore<Integer>(), clientConfig);
    }

    @Test
    public void testHandshake() throws Exception
    {

        final Integer CLIENT = 9;
        final Integer SERVER = 10;

        IReaderWriter _sslServerTransport = new IReaderWriter() {
            byte[] remainingData = new byte[0];
            @Override
            public byte[] read(ReadEvent readEvent)
            {
                System.out.println("SSLServerTransport read event : " + readEvent);
                switch (readEvent)
                {
                    case REMAINING_UNPROCESSED_DATA:
                        byte[] returnData = remainingData;
                        remainingData = new byte[0];
                        return returnData;
                    default:
                        return new byte[0];
                }
            }

            @Override
            public boolean hasData(ReadEvent readEvent)
            {
                return (remainingData.length > 0);
            }

            @Override
            public void write(WriteEvent writeEvent, byte[] dataToBeWritten)
            {
                System.out.println("SSLServerTransport write event : " + writeEvent);
                System.out.println("SSLServerTransport S > C: " + dataToBeWritten.length);
                System.out.println("SSLServerTransport SSLClient| Received data");
                try {
                    switch (writeEvent)
                    {
                        case REMAINING_UNPROCESSED_DATA:
                            byte[] temp = new byte[remainingData.length + dataToBeWritten.length];
                            System.arraycopy(remainingData, 0, temp, 0, remainingData.length);
                            System.arraycopy(dataToBeWritten, 0, temp, remainingData.length, dataToBeWritten.length);
                            remainingData = temp;
                            break;
                        case HANDSHAKE_COMPLETE_STATUS:
                            System.out.println("Server Done");
                            assertTrue(true);
                            return;
                        case WRAPPED_OUTPUT:
                            sslClient.decrypt(SERVER, dataToBeWritten);
                            break;
                        case UNWRAPPED_OUTPUT:
                            break;
                    }
                    sslServer.shakeHands(CLIENT);
                } catch (IOException e) {
                    System.out.println("S > C: : IOEXCEPTION" );
                }
            }
        };

        IReaderWriter _sslClientTransport = new IReaderWriter()
        {
            byte[] remainingData = new byte[0];
            @Override
            public byte[] read(ReadEvent readEvent)
            {
                System.out.println("SSLClientTransport read event : " + readEvent);
                switch (readEvent)
                {
                    case REMAINING_UNPROCESSED_DATA:
                        byte[] returnData = remainingData;
                        remainingData = new byte[0];
                        return returnData;
                    default:
                        return new byte[0];
                }
            }

            @Override
            public boolean hasData(ReadEvent readEvent)
            {
                return remainingData.length > 0;
            }

            @Override
            public void write(WriteEvent writeEvent, byte[] dataToBeWritten)
            {
                System.out.println("SSLClientTransport write event : " + writeEvent );
                System.out.println("SSLClientTransport C > S: " + dataToBeWritten.length);
                System.out.println("SSLClientTransport SSLServer| Received data");
                try{
                    switch (writeEvent)
                    {
                        case REMAINING_UNPROCESSED_DATA:
                            byte[] temp = new byte[remainingData.length + dataToBeWritten.length];
                            System.arraycopy(remainingData, 0, temp, 0, remainingData.length);
                            System.arraycopy(dataToBeWritten, 0, temp, remainingData.length, dataToBeWritten.length);
                            remainingData = temp;
                            break;
                        case HANDSHAKE_COMPLETE_STATUS:
                            System.out.println("Client Done");
                            assertTrue(true);
                            return;
                        case WRAPPED_OUTPUT:
                            sslServer.decrypt(CLIENT, dataToBeWritten);
                            break;
                        case UNWRAPPED_OUTPUT:
                            break;
                    }
                    sslClient.shakeHands(SERVER);
                }
                catch (IOException e)
                {
                    System.out.println("C > S: : IOEXCEPTION" );
                }
            }
        };

        sslServer.initSSLEngine(CLIENT, _sslServerTransport);

        sslClient.initSSLEngine(SERVER, _sslClientTransport);
        System.out.println("SSLServer| handshake begins");
        sslServer.beginSSLHandshake(CLIENT);

        System.out.println("SSLCLIENT| handshake begins");
        sslClient.beginSSLHandshake(SERVER);
    }

    @Test
    public void testDataSent() throws Exception
    {
        final Integer CLIENT = 9;
        final Integer SERVER = 10;

        final String sampleString = "data data data data data data data data data data data data data data data data  data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data ";
        final byte[] sampleData = sampleString.getBytes();


/*
        SSLTransport<Integer> serverTransport = new SSLTransport<Integer>()
        {
            @Override
            public void send(Integer key, byte[] data) throws IOException
            {
                sslClient.decrypt(SERVER, data);
                sslClient.shakeHands(SERVER);
            }
        };
        SSLTransport<Integer> clientTransport = new SSLTransport<Integer>()
        {
            @Override
            public void send(Integer key, byte[] data) throws IOException
            {
                sslServer.decrypt(CLIENT, data);
                if (sslClient.isHandshakeCompleted(SERVER))
                {
                    byte[] decryptedBytes = Arrays.copyOfRange(decryptedData.array(), 0, decryptedData.position());
                    String decryptedString = new String(decryptedBytes);
                    assertEquals(sampleString.length(), decryptedString.length());
                    assertTrue(sampleString.equals(decryptedString));
                    return;
                }
                if (!sslServer.isHandshakeCompleted(CLIENT))
                {
                    sslServer.shakeHands(CLIENT);
                    return;
                }
            }
        };
*/

/*
        sslServer.initSSLEngine(CLIENT, new HandshakeCompletedListener()
        {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                assertTrue(true);
            }
        });
        sslClient.initSSLEngine(SERVER, new HandshakeCompletedListener()
        {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                try
                {
                    sslClient.encrypt(SERVER, sampleData);
                }
                catch (IOException e)
                {
                    fail(e.toString());
                }
            }
        });
*/

        sslServer.beginSSLHandshake(CLIENT);

        sslClient.beginSSLHandshake(SERVER);
    }
}
