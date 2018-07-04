package pcap;

import java.io.*;

public class PcapLoad {

    private static final int[] AMR_FRAME_SIZE = new int[] {
            17, 23, 32, 36, 40, 46, 50, 58, 60
    };

    private static final byte[] AMR_HEADER = { 0x23, 0x21, 0x41, 0x4D, 0x52, 0x2D, 0x57, 0x42, 0x0A };

    public void pcapFileOpen(String fileName) throws FileNotFoundException
    {
        InputStream in;
        OutputStream out;
        BufferedInputStream bis;
        BufferedOutputStream bos ;

        in=new FileInputStream(new File(fileName));
        bis = new BufferedInputStream(in);

        int comma = fileName.lastIndexOf(".");
        String amffile = String.format("%samr", fileName.substring(0, comma + 1));

        System.out.println( "Output File Name [" + amffile + "]");

        out=new FileOutputStream(new File(amffile));
        bos = new BufferedOutputStream(out);

        int len;

        try {
            bos.write(AMR_HEADER, 0, AMR_HEADER.length);

            int PCAPHERDER_LEN = 24;
            int PL_LEN = 16;
            int ETH_HERDER_LEN = 14;
            int IP_HERDER_LEN = 20;
            int UDP_HERDER_LEN = 8;
            int RTP_HERDER_LEN = 12;
            int CMR_LEN = 1;
            int FT_LEN = 1;
            byte[] ph = new byte[PL_LEN];
            byte[] pcapHeader = new byte[PCAPHERDER_LEN];
            byte[] ethHeader = new byte[ETH_HERDER_LEN];
            byte[] ipHeader = new byte[IP_HERDER_LEN];
            byte[] udpHeader = new byte[UDP_HERDER_LEN];
            byte[] rtpHeader = new byte[RTP_HERDER_LEN];
            byte[] cmr = new byte[CMR_LEN];
            byte[] ft = new byte[FT_LEN];

            bis.read( pcapHeader,0,PCAPHERDER_LEN );

            while ((len = bis.read( ph,0,PL_LEN )) >= 0) {
                bis.read( ethHeader,0,ETH_HERDER_LEN );
                bis.read( ipHeader,0,IP_HERDER_LEN );
                bis.read( udpHeader,0,UDP_HERDER_LEN );
                this.viewUdpHeader(udpHeader);

                bis.read( rtpHeader,0,RTP_HERDER_LEN );
                this.viewRtpHeader(rtpHeader);

                bis.read( cmr,0,CMR_LEN );

                len = bis.read( ft,0,FT_LEN );
                bos.write(ft, 0, len);
                int frameType= ((ft[0] & 0xff) >> 3) & 0x0f;
                int frameLen = AMR_FRAME_SIZE[frameType];
                byte[] frame = new byte[frameLen];

                len = bis.read( frame,0,frameLen );
                bos.write(frame, 0, len);
            }

            bos.close();
            bis.close();
            in.close();
            out.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println( "Output File Name Convert End [" + amffile + "]");
    }

    String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder();
        for(final byte b: a)
            sb.append(String.format("%02x ", b&0xff));
        return sb.toString();
    }

    private static void viewRtpHeader(byte [] rtpHeader)
    {
        byte[] sequence = new byte[2];
        System.arraycopy(rtpHeader, 2, sequence, 0, sequence.length);

        long seq = toUnsignedLong(sequence);

        byte[] timestampBuf = new byte[4];
        System.arraycopy(rtpHeader, 4, timestampBuf, 0, timestampBuf.length);

        long timestamp = toUnsignedInt(timestampBuf);

        byte[] ssrc = new byte[4];
        System.arraycopy(rtpHeader, 8, ssrc, 0, ssrc.length);

        long ssrcInt = toUnsignedInt(ssrc);


        byte[] payload = new byte[1];

        payload[0] = (byte) (rtpHeader[1] & 0xff << 1);
        int payloadtype =  (payload[0] & 0xff >> 1);

        int mark= ((rtpHeader[1] & 0xff) >> 7) & 0x0f;

        System.out.println( "amrtype :"+payloadtype+" mark :"+mark+" sequence : " + seq + " timestamp : " + timestamp + " ssrc : " + ssrcInt);
    }

    private static void viewUdpHeader(byte [] udpHeader)
    {

        byte[] srcPortBuff = new byte[2];
        System.arraycopy(udpHeader, 0, srcPortBuff, 0, srcPortBuff.length);
        long srcPort = toUnsignedLong(srcPortBuff);

        byte[] dstPortBuff = new byte[2];
        System.arraycopy(udpHeader, 2, dstPortBuff, 0, dstPortBuff.length);
        long dstPort = toUnsignedLong(dstPortBuff);

        System.out.println( "Source Port : " + srcPort + " Dst Port : " + dstPort);

        byte[] payloadLenBuff = new byte[2];
        System.arraycopy(udpHeader, 4, payloadLenBuff, 0, payloadLenBuff.length);
        long payloadLen = toUnsignedLong(payloadLenBuff);

        System.out.println( "Source Port : " + srcPort + " Dst Port : " + dstPort + " Payload Length : " + payloadLen);
    }

    public static final long toUnsignedInt(byte[] b) {
        long l = 0;

        l |= b[0] & 0xFF;
        l <<= 8;
        l |= b[1] & 0xFF;
        l <<= 8;
        l |= b[2] & 0xFF;
        l <<= 8;
        l |= b[3] & 0xFF;

        return l;
    }

    public static final long toUnsignedLong(byte[] b) {
        long l = 0;

        l |= b[0] & 0xFF;
        l <<= 8;
        l |= b[1] & 0xFF;

        return l;
    }
}
