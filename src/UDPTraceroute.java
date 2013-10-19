import static com.savarese.rocksaw.net.RawSocket.*;
import static org.savarese.vserv.tcpip.UDPPacket.*;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Enumeration;

import org.savarese.vserv.tcpip.*;

import com.savarese.rocksaw.net.*;

public class UDPTraceroute {

	public static RawSocket send_socket;
	public static RawSocket rcv_socket;
	public static UDPPacket send_packet;
	public static UDPPacket rcv_packet;
	
	public static final String PAYLOAD_STRING = "CSCI 4720 Jan-Henrik Saily De La Pena";
	
	public static final int TIMEOUT_LENGTH = 10000;
	public static final int IPPACKET_HEADER_LENGTH = 20;
	public static final int UDP_HEADER_LENGTH = 8;
	public static final int PAYLOAD_LENGTH = PAYLOAD_STRING.getBytes().length;
	
	public static final int IP_VERSION = 4;
	public static final int IP_HEADER_WORD_LENGTH = 5;
	public static final int IP_TYPE_OF_SERVICE = 0;
	public static int IP_DATAGRAM_SIZE = IPPACKET_HEADER_LENGTH + UDP_HEADER_LENGTH + PAYLOAD_LENGTH;
	public static final int IP_ID = 0;
	public static final int IP_FLAGS = 0;
	public static final int IP_FRAG_OFFSET = 0;
	public static int IP_TTL = 1;
	public static final int IP_PROTOCOL = 17;
	public static int IP_HEADERCHECKSUM = 0;
	public static InetAddress IP_SOURCE_ADDRESS = null;
	public static InetAddress IP_DEST_ADDRESS = null;
	
	public static final int UDP_SOURCE_PORT = 7302;
	public static int UDP_DEST_PORT = 0;
	public static int UDP_HEADER_CHECKSUM = 0;
	
	public static byte[] send_data;
	public static byte[] rcv_data;
	public static byte[] rcv_address;
	
	public static int MAX_HOPS = 10;
	public static boolean experimental_check = true;
	
	public static void main(String[] args) throws Exception {
		
		if (args.length < 5 || args.length > 6) {
			System.err.println("You need to run this program as:\njava <library_parameters> UDPTraceroute -p <UDP_dst_port> -h <max_hops> <IP_ADDRESS>");
			System.err.println("Or optionally as:\njava <library_parameters> UDPTraceroute -p <UDP_dst_port> -h <max_hops> <IP_ADDRESS> <boolean>");
			System.err.println("where the boolean value decides whether or not an 'experimental' packet error checking is used to make sure the ICMP's recieved aren't random strays. Defaults to \'true\'.");
			System.exit(0);
		}else {
			if (args[0].equalsIgnoreCase("-p")){
				UDP_DEST_PORT = Integer.parseInt(args[1]);
			} else {
				System.err.println("You need to run this program as:\njava <library_parameters> UDPTraceroute -p <UDP_dst_port> -h <max_hops> <IP_ADDRESS>");
				System.err.println("Or optionally as:\njava <library_parameters> UDPTraceroute -p <UDP_dst_port> -h <max_hops> <IP_ADDRESS> <boolean>");
				System.err.println("where the boolean value decides whether or not an 'experimental' packet error checking is used to make sure the ICMP's recieved aren't random strays. Defaults to \'true\'.");
				System.exit(0);
			}
			
			if (args[2].equalsIgnoreCase("-h")) {
				MAX_HOPS = Integer.parseInt(args[3]);
				IP_DEST_ADDRESS = InetAddress.getByName(args[4]);
			} else {
				System.err.println("You need to run this program as:\njava <library_parameters> UDPTraceroute -p <UDP_dst_port> -h <max_hops> <IP_ADDRESS>");
				System.err.println("Or optionally as:\njava <library_parameters> UDPTraceroute -p <UDP_dst_port> -h <max_hops> <IP_ADDRESS> <boolean>");
				System.err.println("where the boolean value decides whether or not an 'experimental' packet error checking is used to make sure the ICMP's recieved aren't random strays. Defaults to \'true\'.");
				System.exit(0);
			}
			
			if (args.length == 6) {
				if (args[5].equalsIgnoreCase("true")) {
					experimental_check = true;
				} else if (args[5].equalsIgnoreCase("false")) {
					experimental_check = false;
				} else {
					System.err.println("The last optional argument needs to be a \'true\' or \'false\'. Assuming true.");
				}
			}
		}
		IP_SOURCE_ADDRESS = getLocalIP();
		InetAddress temp = null;
		System.out.println(IP_SOURCE_ADDRESS.getHostAddress() + " | " + IP_DEST_ADDRESS.getHostAddress());
		do {
			long startTime = System.nanoTime();  
			temp = getNextJump();
			long estimatedTime = System.nanoTime() - startTime;
			double calcTime = (double)estimatedTime / 1000000.0;
			if (temp == null) {
				temp = InetAddress.getByName("0.0.0.0");
				System.out.println("TTL = " + IP_TTL + " | HopIP = XXX.XXX.XXX | Time = (timeout)");
			} else {
				if (experimental_check == true) {
					ICMPPacket temp_packet = new ICMPEchoPacket(1500);
					temp_packet.setData(rcv_data);
					byte[] temp_data = new byte[temp_packet.getICMPDataByteLength()];
					for (int i = 0; i < 28; i++) { // 28 is IP + UDP packet standard header byte length
						temp_data[i] = rcv_data[i + temp_packet.getCombinedHeaderByteLength()];
					}
					rcv_packet = new UDPPacket(28);
					rcv_packet.setData(temp_data);
					if (rcv_packet.getSourcePort() != UDP_SOURCE_PORT) {
						IP_TTL--;
						MAX_HOPS++;
					} else {
						System.out.println("TTL = " + IP_TTL + " | HopIP = " + temp.getHostAddress() + " | Time = " + calcTime + " ms");
					}
				} else {
					System.out.println("TTL = " + IP_TTL + " | HopIP = " + temp.getHostAddress() + " | Time = " + calcTime + " ms");
				}
			}
			IP_TTL++;
			MAX_HOPS--;
		} while(temp.hashCode() != IP_DEST_ADDRESS.hashCode() && MAX_HOPS > 0);
	}
	
	private static InetAddress getNextJump() throws Exception {
		send_socket = new RawSocket();
		rcv_socket = new RawSocket();
		
		rcv_data = new byte[1500];
		rcv_address = new byte[4];
		
		send_socket.open(PF_INET, getProtocolByName("udp"));
		rcv_socket.open(PF_INET, getProtocolByName("icmp"));
		rcv_socket.setReceiveTimeout(TIMEOUT_LENGTH);
		send_socket.setIPHeaderInclude(true);
		
		/* Finish putting header together BEGIN */
		send_data = new byte[IPPACKET_HEADER_LENGTH + LENGTH_UDP_HEADER + PAYLOAD_LENGTH];
		send_packet = new UDPPacket(send_data.length);
		send_packet.setData(send_data);
		
		send_packet.setIPVersion(IP_VERSION);
		send_packet.setIPHeaderLength(IP_HEADER_WORD_LENGTH);
		send_packet.setTypeOfService(IP_TYPE_OF_SERVICE);
		send_packet.setIPPacketLength(IP_DATAGRAM_SIZE);
		send_packet.setIdentification(IP_ID);
		send_packet.setIPFlags(IP_FLAGS);
		send_packet.setFragmentOffset(IP_FRAG_OFFSET);
		send_packet.setTTL(IP_TTL);
		send_packet.setProtocol(IP_PROTOCOL);
		send_packet.setSourceAsWord(IP_SOURCE_ADDRESS.hashCode());
		send_packet.setDestinationAsWord(IP_DEST_ADDRESS.hashCode());
		
		send_packet.setSourcePort(UDP_SOURCE_PORT);
		send_packet.setDestinationPort(UDP_DEST_PORT);
		send_packet.setUDPPacketLength(UDP_HEADER_LENGTH + PAYLOAD_LENGTH);
		send_packet.setUDPDataByteLength(PAYLOAD_LENGTH);
		setUDPPayload(PAYLOAD_STRING);
		
		send_packet.computeIPChecksum(true);
		send_packet.computeUDPChecksum(true);
		/* Finish putting header together END */
		
		send_socket.write(IP_DEST_ADDRESS, send_data);
		//send_socket.write(IP_DEST_ADDRESS, send_data, IPPACKET_HEADER_LENGTH, LENGTH_UDP_HEADER + PAYLOAD_LENGTH);
		try {
			rcv_socket.read(rcv_data, rcv_address);
		} catch(Exception e) {
			send_socket.close();
			rcv_socket.close();
			return null;
		}
		send_socket.close();
		rcv_socket.close();
		return InetAddress.getByAddress(rcv_address);
	}
	
	private static InetAddress getLocalIP() throws UnknownHostException {
		try {
			Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
			for (NetworkInterface netint : Collections.list(nets)){
				//if (netint.getName().equals("en1")) {
				if (netint.getName().equals("eth0")) {
					Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
					for (InetAddress inetAddress : Collections.list(inetAddresses)) {
						// look only for ipv4 addresses
						if (inetAddress instanceof Inet6Address)
							continue;
							return inetAddress;
						}
					}
				}
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		// Hopefully we don't get here, not sure if this one will work
		return InetAddress.getByName("myip.local");
	}
	
	private static void setUDPPayload(String pl) {
		byte[] temp = pl.getBytes();
		for(int i = 0; i < temp.length; i++) {
			send_data[i + send_packet.getCombinedHeaderByteLength()] = temp[i];
		}
	}
}