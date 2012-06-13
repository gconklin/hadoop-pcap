package net.ripe.hadoop.pcap.packet;

import java.util.HashMap;
import java.util.Map;

public class Packet extends HashMap<String, Object> {
	private static final long serialVersionUID = 8723206921174160146L;

  public static final String ETHERTYPE    = "ether_type";
	public static final String TIMESTAMP = "ts";
	public static final String TTL = "ttl";
	public static final String PROTOCOL = "protocol";
	public static final String SRC = "src";
	public static final String DST = "dst";
	public static final String SRC_PORT = "src_port";
	public static final String DST_PORT = "dst_port";
	public static final String LEN = "len";
	public static final String UDPSUM = "udpsum";
  public static final String FRAGMENTED         = "frag";
  public static final String PAYLOAD_LEN        = "payload_len";
  public static final String EXT_HEADER_COUNT   = "ext_count";
  public static final String EXT_HEADERS        = "ext_headers";

	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		for (Map.Entry<String, Object> entry : entrySet()) {
			sb.append(entry.getKey());
			sb.append('=');
			sb.append(entry.getValue());
			sb.append(',');
		}
		if (sb.length() > 0)
			return sb.substring(0, sb.length() - 1);
		return null;
	}
}
