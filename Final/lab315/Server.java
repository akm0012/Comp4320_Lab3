import java.net.*; // for DatagramSocket, DatagramPacket, and InetAddress 
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.*; // for IOException

public class Server { 
	
	private static final int BUFFMAX = 255;
	private static final byte GROUPID = 15;
	
	public static void main(String[] args) throws IOException { 

		int servPort;
		
		if (args.length != 1) { // Test for correct argument list
			throw new IllegalArgumentException("Parameter(s): <Port>");
		}
		else {
			try {
				servPort = Integer.parseInt(args[0]);
			}
			catch (Exception e) {
				throw new IllegalArgumentException("Parameter(s): <Port>");
			}
		}
		
		DatagramSocket socket = new DatagramSocket(servPort);
		DatagramPacket packet = new DatagramPacket(new byte[BUFFMAX], BUFFMAX);
		boolean error = false;
		
		boolean clientWaiting = false;
		InetAddress clientAddress = null;
		short clientPort = 0;
		
		// Run forever
		System.out.println("Server awaiting connections...\r\n");
		while (true) { 
			
			socket.receive(packet); // Receive packet from client 
			System.out.println("Handling client at " + packet.getAddress().getHostAddress() + " on port " + packet.getPort());
			
			ArrayList<Byte> bytesToSend = new ArrayList<Byte>();
			byte[] byteArray = null;
			
			//Check for error case 2
			if (packet.getLength() != 5) {
				bytesToSend.add((byte) 0x12);
				bytesToSend.add((byte) 0x34);
				bytesToSend.add((byte) GROUPID);
				bytesToSend.add((byte) 0);
				bytesToSend.add((byte) 2);
				
				byteArray = new byte[bytesToSend.size()];
				for (int i = 0; i < bytesToSend.size(); i++) {
					byteArray[i] = bytesToSend.get(i);
				}
				
				System.out.println("\t...Invalid packet length");
				error = true;
			}
			
			//Check for error case 1
			else if (packet.getData() [0] != 0x12 || packet.getData() [1] != 0x34) {
				bytesToSend.add((byte) 0x12);
				bytesToSend.add((byte) 0x34);
				bytesToSend.add((byte) GROUPID);
				bytesToSend.add((byte) 0);
				bytesToSend.add((byte) 1);
				
				byteArray = new byte[bytesToSend.size()];
				for (int i = 0; i < bytesToSend.size(); i++) {
					byteArray[i] = bytesToSend.get(i);
				}
				
				System.out.println("\t...Invalid magic number");
				error = true;
			}
			
			//Check for error case 3
			else {
				
				byte[] portIn = Arrays.copyOfRange(packet.getData(),3,5);
				ByteBuffer wrapped = ByteBuffer.wrap(portIn);
				short port = wrapped.getShort();
				
				if (port < packet.getData()[2] * 5 + 10010 || port > packet.getData()[2] * 5 + 4 + 10010) {
					
					bytesToSend.add((byte) 0x12);
					bytesToSend.add((byte) 0x34);
					bytesToSend.add((byte) GROUPID);
					bytesToSend.add((byte) 0);
					bytesToSend.add((byte) 4);
					
					byteArray = new byte[bytesToSend.size()];
					for (int i = 0; i < bytesToSend.size(); i++) {
						byteArray[i] = bytesToSend.get(i);
					}
					
					System.out.println("\t...Port number out of range");
					error = true;
				}
			}
			
			//Perform match if no error
			if (!error) {
				if (!clientWaiting) {
					clientWaiting = true;
					clientAddress = packet.getAddress();
					
					byte[] portIn = Arrays.copyOfRange(packet.getData(),3,5);
					ByteBuffer wrapped = ByteBuffer.wrap(portIn);
					short port = wrapped.getShort();
					clientPort = port;
					
					bytesToSend.add((byte) 0x12);
					bytesToSend.add((byte) 0x34);
					bytesToSend.add((byte) GROUPID);
					bytesToSend.add((byte) packet.getData()[3]);
					bytesToSend.add((byte) packet.getData()[4]);
					
					byteArray = new byte[bytesToSend.size()];
					for (int i = 0; i < bytesToSend.size(); i++) {
						byteArray[i] = bytesToSend.get(i);
					}
					
					System.out.println("\t...Client waiting");
				}
				else {
					clientWaiting = false;
					
					ByteBuffer buffer = ByteBuffer.allocate(2);
					buffer.putShort(clientPort);
					
					bytesToSend.add((byte) 0x12);
					bytesToSend.add((byte) 0x34);
					bytesToSend.add((byte) GROUPID);
					bytesToSend.add(clientAddress.getAddress()[0]);
					bytesToSend.add(clientAddress.getAddress()[1]);
					bytesToSend.add(clientAddress.getAddress()[2]);
					bytesToSend.add(clientAddress.getAddress()[3]);
					bytesToSend.add(buffer.get(0));
					bytesToSend.add(buffer.get(1));
					
					byteArray = new byte[bytesToSend.size()];
					for (int i = 0; i < bytesToSend.size(); i++) {
						byteArray[i] = bytesToSend.get(i);
					}
					
					System.out.println("\t...Clients matched");
				}
			}
			else {
				error = false;
			}
			
			//Send result packet
			DatagramPacket newPacket = new DatagramPacket(byteArray, byteArray.length, packet.getAddress(), packet.getPort());
			socket.send(newPacket); // Send new packet back to client 
			
			packet = new DatagramPacket(new byte[BUFFMAX], BUFFMAX);
		}
	}
} 