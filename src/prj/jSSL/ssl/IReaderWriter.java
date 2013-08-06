package prj.jSSL.ssl;

public interface IReaderWriter
{
    /**
     * This function is supposed to return any data associated with the input read event. This data is supposed to be
     * cleared when read using this function. Thus if two consecutive calls are made using same read event then the
     * second call will nothing.
     * @param readEvent
     * @return
     */
    public byte[] read(ReadEvent readEvent);

    public boolean hasData(ReadEvent readEvent);

    /**
     * This function will append the data to the already existing data associated with the same write event. If
     * originally there is no data then this data is associated with the event.
     * @param writeEvent
     * @param dataToBeWritten
     */
    public void write(WriteEvent writeEvent, byte[] dataToBeWritten);
    public enum WriteEvent
    {
        HANDSHAKE_COMPLETE_STATUS, WRAPPED_OUTPUT, REMAINING_UNPROCESSED_DATA, UNWRAPPED_OUTPUT;
    }
    public enum ReadEvent
    {
        REMAINING_UNPROCESSED_DATA;
    }
}
