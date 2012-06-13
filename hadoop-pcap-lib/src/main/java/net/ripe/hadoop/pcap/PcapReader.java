package net.ripe.hadoop.pcap;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import net.ripe.hadoop.pcap.packet.Packet;

public class PcapReader implements Iterable<Packet> {
	public static final Log LOG = LogFactory.getLog(PcapReader.class);

	public static final long MAGIC_NUMBER = 0xA1B2C3D4;
	public static final int HEADER_SIZE = 24;
	public static final int PCAP_HEADER_LINKTYPE_OFFSET = 20;
	public static final int PACKET_HEADER_SIZE = 16;
	public static final int TIMESTAMP_OFFSET = 0;
	public static final int CAP_LEN_OFFSET = 8;
	public static final int ETHERNET_HEADER_SIZE = 14;
	public static final int ETHERNET_TYPE_OFFSET = 12;
	public static final int ETHERNET_TYPE_IP = 0x0800;
	public static final int ETHERNET_TYPE_IPv6 = 0x86dd;
	public static final int ETHERNET_TYPE_8021Q = 0x8100;
	public static final int IP_VHL_OFFSET = 0;	// relative to start of IP header
	public static final int IP_TTL_OFFSET = 8;	// relative to start of IP header
	public static final int IP_PROTOCOL_OFFSET = 9;	// relative to start of IP header
	public static final int IP_SRC_OFFSET = 12;	// relative to start of IP header
	public static final int IP_DST_OFFSET = 16;	// relative to start of IP header

	public static final int IP6_HOP_OFFSET = 7;	// relative to start of IP header
	public static final int IP6_SRC_OFFSET = 8;	// relative to start of IP header
	public static final int IP6_DST_OFFSET = 24;	// relative to start of IP header
  public static final int IP6_NEXT_HEADER_OFFSET = 6; // relative to start of IP header
  public static final int IP6_PAYLOAD_LEN_OFFSET = 4;
  public static final int IP6_EXT_FRAGMENT = 44;
  public static final int IP6_NO_NEXT_HEADER = 59;

  public static final int UDP_HEADER_SIZE = 8;
	public static final int PROTOCOL_HEADER_SRC_PORT_OFFSET = 0;
	public static final int PROTOCOL_HEADER_DST_PORT_OFFSET = 2;
	public static final int TCP_HEADER_DATA_OFFSET = 12;
	public static final String PROTOCOL_ICMP = "ICMP";
	public static final String PROTOCOL_ICMPv6 = "ICMPv6";
	public static final String PROTOCOL_TCP = "TCP";
	public static final String PROTOCOL_UDP = "UDP";
	public static final String PROTOCOL_GRE = "GRE";
	public static final String PROTOCOL_RSVP = "RSVP";

	public static final String IPv6_HOP_BY_HOP  = "HopByHop";
	public static final String IPv6_ROUTING     = "Routing";
	public static final String IPv6_FRAGMENT    = "Fragment";
	public static final String IPv6_AUTH_HEADER = "AuthHeader";
	public static final String IPv6_ESP         = "ESP";
	public static final String IPv6_DEST_OPTS   = "DestOpts";
	public static final String IPv6_MOBILITY    = "Mobility";

	public static final boolean debug = false;

	private final DataInputStream is;
	private Iterator<Packet> iterator;
	private LinkType linkType;
	private boolean caughtEOF = false;
	private int nPktsRead = 0;

	public PcapReader(DataInputStream is) throws IOException {
		this.is = is;
		iterator = new PacketIterator();

		byte[] pcapHeader = new byte[HEADER_SIZE];
		if (!readBytes(pcapHeader)) {
			//
			// This special check for EOF is because we don't want
			// PcapReader to barf on an empty file.  This is the only
			// place we check caughtEOF.
			//
			if (caughtEOF) {
				System.out.println("skipping empty file");
				return;
			}
			throw new IOException("Couldn't read PCAP header");
		}

		if (!validateMagicNumber(pcapHeader))
			throw new IOException("Not a PCAP file (Couldn't find magic number)");

		long linkTypeVal = PcapReaderUtil.convertInt(pcapHeader, PCAP_HEADER_LINKTYPE_OFFSET);
		if ((linkType = getLinkType(linkTypeVal)) == null)
			throw new IOException("Unsupported link type: " + linkTypeVal);
		if (debug)
			System.out.println("linktype = " + linkTypeVal);
	}

	// Only use this constructor for testcases
	protected PcapReader(LinkType lt) {
		this.is = null;
		linkType = lt;
	}

	private int getUdpChecksum(byte[] packetData, int ipStart, int ipHeaderLen) {
    try
    {
      /*
       * No Checksum on this packet?
       */
      if (packetData[ipStart + ipHeaderLen + 6] == 0 &&
          packetData[ipStart + ipHeaderLen + 7] == 0)
        return -1;

      /*
       * Build data[] that we can checksum.  Its a pseudo-header
       * followed by the entire UDP packet.
       */
      byte data[] = new byte[packetData.length - ipStart - ipHeaderLen + 12];
          short answer;
      int sum = 0;
      System.arraycopy(packetData, ipStart + IP_SRC_OFFSET,      data, 0, 4);
      System.arraycopy(packetData, ipStart + IP_DST_OFFSET,      data, 4, 4);
      data[8] = 0;
      data[9] = 17;	/* IPPROTO_UDP */
      System.arraycopy(packetData, ipStart + ipHeaderLen + 4,    data, 10, 2);
      System.arraycopy(packetData, ipStart + ipHeaderLen,        data, 12, packetData.length - ipStart - ipHeaderLen);
      for (int i = 0; i<data.length; i++) {
        int j = data[i];
        if (j < 0)
          j += 256;
        /*System.out.format("data[%d] = %x/%d\t", i, j, j);*/
        sum += j << (i % 2 == 0 ? 8 : 0);
        /*System.out.format("sum      = %x\n", sum);*/
      }
      sum = (sum >> 16) + (sum & 0xffff);
      /*System.out.format("\t\tsum      = %x\n", sum);*/
      sum += (sum >> 16);
      /*System.out.format("\t\tsum      = %x\n", sum);*/
      /*System.out.format("\t\treturn   = %x\n", (~sum) & 0xffff);*/
      return (~sum) & 0xffff;
    }
    catch ( ArrayIndexOutOfBoundsException ex )
    {
      return -1;
    }
	}

	private Packet nextPacket() {
		byte[] pcapPacketHeader = new byte[PACKET_HEADER_SIZE];
		if (!readBytes(pcapPacketHeader))
			return null;

		Packet packet = createPacket();

		long packetTimestamp = PcapReaderUtil.convertInt(pcapPacketHeader, TIMESTAMP_OFFSET);
		packet.put(Packet.TIMESTAMP, packetTimestamp);

		long packetSize = PcapReaderUtil.convertInt(pcapPacketHeader, CAP_LEN_OFFSET);
		byte[] packetData = new byte[(int)packetSize];
		if (!readBytes(packetData))
			return packet;

		packet.put(Packet.ETHERTYPE, getEtherType(packetData) );

		int ipStart = findIPStart(packetData);
		if (ipStart == -1)
			return packet;

    int ver = getInternetProtocolHeaderVersion(packetData, ipStart);
		if (ver == 4) {
			buildInternetProtocolV4Packet(packet, packetData, ipStart);
	
			String protocol = (String)packet.get(Packet.PROTOCOL);
			if (PROTOCOL_UDP == protocol || 
					PROTOCOL_TCP == protocol) {
	
		    int ipHeaderLen = getInternetProtocolHeaderLength(packetData, ipStart);

				byte[] packetPayload = buildTcpAndUdpPacket(packet, packetData, ipStart, ipHeaderLen);
				processPacketPayload(packet, packetPayload);
			}
		}
    else if ( ver == 6 )
    {
      buildInternetProtocolV6Packet(packet, packetData, ipStart);

      int ipv6dataStart = findIPv6DataStart( packet, packetData, ipStart );

      String protocol = (String)packet.get(Packet.PROTOCOL);
      if (PROTOCOL_UDP == protocol ||
          PROTOCOL_TCP == protocol) {

        byte[] packetPayload = buildTcpAndUdpPacket( packet, packetData, ipStart, ipv6dataStart );
        processPacketPayload(packet, packetPayload);
      }
    }

		nPktsRead++;
		return packet;
	}

	protected Packet createPacket() {
		return new Packet();
	}

	protected void processPacketPayload(Packet packet, byte[] payload) {}

	protected boolean validateMagicNumber(byte[] pcapHeader) {
		return PcapReaderUtil.convertInt(pcapHeader) == MAGIC_NUMBER;
	}

	protected enum LinkType {
		NULL, EN10MB, RAW, LOOP
	}

	protected LinkType getLinkType(long linkTypeVal) {
		switch ((int)linkTypeVal) {
			case 0:
				return LinkType.NULL;
			case 1:
				return LinkType.EN10MB;
			case 101:
				return LinkType.RAW;
			case 108:
				return LinkType.LOOP;
		}
		return null;
	}

	// see: http://en.wikipedia.org/wiki/EtherType
	protected String getEtherType(byte[] packet) {
		if (linkType == LinkType.EN10MB) {
				int etherType = PcapReaderUtil.convertShort(packet, ETHERNET_TYPE_OFFSET);
				switch ( etherType ) {
					case 0x0800:
						return "IPv4";

					case 0x0806:
						return "arp";

					case 0x8035:
						return "rarp";

					case 0x86dd:
						return "IPv6";

					case 0x8100:
						return "vlan";
				}

				return String.format( "0x%04x", etherType );
		}

		return "";
	}

	protected int findIPStart(byte[] packet) {
		switch (linkType) {
			case NULL:
				return 0;
			case EN10MB:
				int start = ETHERNET_HEADER_SIZE;
				int etherType = PcapReaderUtil.convertShort(packet, ETHERNET_TYPE_OFFSET);
				if (etherType == ETHERNET_TYPE_8021Q) {
					etherType = PcapReaderUtil.convertShort(packet, ETHERNET_TYPE_OFFSET + 4);
					start += 4;
				}
				if (etherType == ETHERNET_TYPE_IP || etherType == ETHERNET_TYPE_IPv6 )
					return start;
				break;
			case RAW:
				return 0;
			case LOOP:
				return 4;
		}
		return -1;
	}

	private int getInternetProtocolHeaderLength(byte[] packet, int ipStart) {
		return (packet[ipStart + IP_VHL_OFFSET] & 0xF) * 4;
	}

	private int getInternetProtocolHeaderVersion(byte[] packet, int ipStart) {
		return (packet[ipStart + IP_VHL_OFFSET] >> 4) & 0xF;
	}

	private int getTcpHeaderLength(byte[] packet, int tcpStart) {
		int dataOffset = tcpStart + TCP_HEADER_DATA_OFFSET;
		return ((packet[dataOffset] >> 4) & 0xF) * 4;
	}

	private void buildInternetProtocolV4Packet(Packet packet, byte[] packetData, int ipStart) {
		int ttl = packetData[ipStart + IP_TTL_OFFSET] & 0xFF;
		packet.put(Packet.TTL, ttl);

		int protocol = packetData[ipStart + IP_PROTOCOL_OFFSET];
		packet.put(Packet.PROTOCOL, PcapReaderUtil.convertProtocolIdentifier(protocol));

		String src = PcapReaderUtil.convertAddress(packetData, ipStart + IP_SRC_OFFSET);
		packet.put(Packet.SRC, src);

		String dst = PcapReaderUtil.convertAddress(packetData, ipStart + IP_DST_OFFSET);
		packet.put(Packet.DST, dst);
	}

	private void buildInternetProtocolV6Packet(Packet packet, byte[] packetData, int ipStart) {
		int ttl = packetData[ipStart + IP6_HOP_OFFSET] & 0xFF;
		packet.put(Packet.TTL, ttl);

//		int protocol = packetData[ipStart + IP_PROTOCOL_OFFSET];
//		packet.put(Packet.PROTOCOL, PcapReaderUtil.convertProtocolIdentifier(protocol));

    int payloadLen = PcapReaderUtil.convertShort( packetData, ipStart + IP6_PAYLOAD_LEN_OFFSET );
    packet.put( Packet.PAYLOAD_LEN, payloadLen );

		String src = PcapReaderUtil.convertIPv6Address(packetData, ipStart + IP6_SRC_OFFSET);
		packet.put(Packet.SRC, src);

		String dst = PcapReaderUtil.convertIPv6Address(packetData, ipStart + IP6_DST_OFFSET);
		packet.put(Packet.DST, dst);
/*
    StringBuilder s = new StringBuilder( 200 );
    for ( int i = 0; i < 40; ++i )
    {
      s.append( String.format( "%02x ", packetData[ipStart + i] ) );
    }
    System.out.println( s.toString() );
*/
  }

  private void addExtHeader( Packet packet, String header )
  {
    String headers = (String)packet.get( Packet.EXT_HEADERS );

    if ( headers == null )
      headers = "";

    headers += "[" + header + "]";
    packet.put( Packet.EXT_HEADERS, headers );
  }

  private int findIPv6DataStart( Packet packet, byte[] packetData, int ipStart ) {
    int   headerCount = 0;
    int   dataStart = 40;
    int   next = packetData[ipStart + IP6_NEXT_HEADER_OFFSET] & 0xFF;

    boolean found = false;
    while ( (ipStart + dataStart) < packetData.length )
    {
      String headerType = null;
      boolean isExtHeader = PcapReaderUtil.isIPv6ExtHeader( next );

      if ( isExtHeader )
        headerType = PcapReaderUtil.convertIPv6ExtHeaderIdentifier( next );
      else
        headerType = PcapReaderUtil.convertProtocolIdentifier( next );

      addExtHeader( packet, headerType );

      if ( next == IP6_NO_NEXT_HEADER )
      {
        dataStart = -1;
        break;
      }

      if ( !isExtHeader )
      {
        packet.put( Packet.PROTOCOL, headerType );
        break;
      }
      
      ++headerCount;
      if ( next == IP6_EXT_FRAGMENT )
      {
        packet.put( Packet.FRAGMENTED, true );

        next = packetData[ipStart + dataStart] & 0xFF;
        dataStart += 8;
      }
      else
      {
        next = packetData[ipStart + dataStart] & 0xFF;

        dataStart += 1 + (packetData[ipStart + dataStart + 1] & 0xFF );
      }
    }

    packet.put( Packet.EXT_HEADER_COUNT, headerCount );

    return dataStart;
  }

	/*
	 * packetData is the entire layer 2 packet read from pcap
	 * ipStart is the start of the IP packet in packetData
	 */
	private byte[] buildTcpAndUdpPacket(Packet packet, byte[] packetData, int ipStart, int ipHeaderLen) {
		packet.put(Packet.SRC_PORT, PcapReaderUtil.convertShort(packetData, ipStart + ipHeaderLen + PROTOCOL_HEADER_SRC_PORT_OFFSET));

		packet.put(Packet.DST_PORT, PcapReaderUtil.convertShort(packetData, ipStart + ipHeaderLen + PROTOCOL_HEADER_DST_PORT_OFFSET));

		int headerSize;
		final String protocol = (String)packet.get(Packet.PROTOCOL);
		if (PROTOCOL_UDP.equals(protocol)) {
			headerSize = UDP_HEADER_SIZE;
			int cksum = getUdpChecksum(packetData, ipStart, ipHeaderLen);
			if (cksum >= 0)
				packet.put(Packet.UDPSUM, cksum);
		} else if (PROTOCOL_TCP.equals(protocol))
			headerSize = getTcpHeaderLength(packetData, ipStart + ipHeaderLen);
		else
			return null;

		int payloadDataStart = ipStart + ipHeaderLen + headerSize;
		byte[] data = readPayload(packetData, payloadDataStart);
		packet.put(Packet.LEN, data.length);
		return data;
	}

	/**
	 * Reads the packet payload and returns it as byte[].
	 * If the payload could not be read an empty byte[] is returned.
	 * @param packetData
	 * @param payloadDataStart
	 * @return payload as byte[]
	 */
	protected byte[] readPayload(byte[] packetData, int payloadDataStart) {
		if (payloadDataStart > packetData.length) {
			LOG.warn("Payload start (" + payloadDataStart + ") is larger than packet data (" + packetData.length + "). Returning empty payload.");
			return new byte[0];
		}
		byte[] data = new byte[packetData.length - payloadDataStart];
		System.arraycopy(packetData, payloadDataStart, data, 0, data.length);
		return data;
	}

	protected boolean readBytes(byte[] buf) {
		try {
			is.readFully(buf);
			return true;
		} catch (EOFException e) {
			// Reached the end of the stream
			caughtEOF = true;
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public Iterator<Packet> iterator() {
		return iterator;
	}

	private class PacketIterator implements Iterator<Packet> {
		private Packet next;

		private void fetchNext() {
			if (next == null)
				next = nextPacket();
		}

		@Override
		public boolean hasNext() {
			fetchNext();
			if (next != null)
				return true;
			if (debug)
				System.out.println ("hasNext() returns false after " + nPktsRead + " packets");
			return false;
		}

		@Override
		public Packet next() {
			fetchNext();
			try {
				return next;
			} finally {
				next = null;
			}
		}

		@Override
		public void remove() {
			// Not supported
		}
	}
}
