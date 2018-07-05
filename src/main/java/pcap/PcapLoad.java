package pcap;

import Audio.AMRWB;
import rtp.RtpPacket;
import udp.UdpPacket;

import java.io.*;

public class PcapLoad {

    private RtpPacket rtpPacket = new RtpPacket( 1024, true);
    private UdpPacket udpPacket = new UdpPacket( 172, true);
    private AMRWB amrwb = new AMRWB( 172, true);

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

        try {
            bos.write(AMR_HEADER, 0, AMR_HEADER.length);

            int PCAPHERDER_LEN = 24;
            int PL_LEN = 16;
            int ETH_HERDER_LEN = 14;
            int IP_HERDER_LEN = 20;
            int UDP_HERDER_LEN = 8;
            byte[] ph = new byte[PL_LEN];
            byte[] pcapHeader = new byte[PCAPHERDER_LEN];
            byte[] ethHeader = new byte[ETH_HERDER_LEN];
            byte[] ipHeader = new byte[IP_HERDER_LEN];
            byte[] udpHeader = new byte[UDP_HERDER_LEN];
            byte[] rtp = new byte[1024];

            bis.read( pcapHeader,0,PCAPHERDER_LEN );

            while (bis.read( ph,0,PL_LEN ) >= 0) {
                bis.read( ethHeader,0,ETH_HERDER_LEN );
                bis.read( ipHeader,0,IP_HERDER_LEN );
                bis.read( udpHeader,0,UDP_HERDER_LEN );
                udpPacket.getBuffer().clear();
                udpPacket.getBuffer().rewind();
                udpPacket.getBuffer().put(udpHeader);
                udpPacket.getBuffer().flip();

                System.out.println("udpPacket : " + udpPacket.toString());

                bis.read( rtp, 0, (int) udpPacket.getUDPLength() - udpHeader.length);

                rtpPacket.getBuffer().clear();
                rtpPacket.getBuffer().rewind();
                rtpPacket.getBuffer().put(rtp);
                rtpPacket.getBuffer().flip();

                int audioLength = (int) udpPacket.getUDPLength() - udpPacket.FIXED_HEADER_SIZE - rtpPacket.FIXED_HEADER_SIZE;
                byte[] audio = new byte[audioLength];

                rtpPacket.getPayload(audio,0, audioLength);


                amrwb.getBuffer().clear();
                amrwb.getBuffer().rewind();
                amrwb.getBuffer().put(audio);
                amrwb.getBuffer().flip();

                System.out.println("Audio : " + amrwb.getAmrDataLength() + byteArrayToHex(amrwb.getAmrData()));

                bos.write(amrwb.getAmrData(), 0, amrwb.getAmrDataLength()-1);
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

    private static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder();
        for(final byte b: a)
            sb.append(String.format("%02x ", b&0xff));
        return sb.toString();
    }
}
