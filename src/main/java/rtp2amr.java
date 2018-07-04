import common.StringUtil;
import pcap.PcapLoad;

import java.io.FileNotFoundException;


public class rtp2amr {

    public static void main(String[] args) {

        int instanceId = 0;
        String rtpPath = null;

        if (args != null && args.length > 0) {
            if (args.length > 0) {
                rtpPath = args[0];
            }
        }

        System.out.println("RTP packet to amr file convert ["+rtpPath+"]");

        PcapLoad pcapLoad = new PcapLoad();

        try {
            pcapLoad.pcapFileOpen(rtpPath);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }


    }
}
