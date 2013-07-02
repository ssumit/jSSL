package prj.jSSL.ssl;

public interface IReaderWriter
{
    public byte[] read(ReadEvent readEvent);
    public void write(WriteEvent writeEvent, byte[] dataToBeWritten);
    public enum WriteEvent
    {
        HANDSHAKE_COMPLETE_STATUS, WRAP_STATE, REMAINING_DATA, UNWRAP_STATE;
    }
    public enum ReadEvent
    {
        REMAINING_DATA;
    }
}
