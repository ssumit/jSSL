package prj.jSSL.ssl;

public interface IReaderWriter
{
    public String read(ReadEvent readEvent);
    public void write(WriteEvent writeEvent, String dataToBeWritten);
    public enum WriteEvent
    {
        HANDSHAKE_COMPLETE_STATUS, WRAP_STATE;
    }
    public enum ReadEvent
    {
        REMAINING_DATA;
    }
}
