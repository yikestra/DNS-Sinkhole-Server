
package il.ac.idc.cs.sinkhole;

import java.net.*;
import java.util.HashSet;
import java.io.*;
import java.util.Scanner;

public class SinkholeServer {

  // Constants / Hard Coded Values
  public static char randomrootserver; // Variable that saves the generated random root server 
  public static byte ref = -64; // 0b11000000 is a constant of type int and 0b11000000= -64
  static final int port = 5300; // UDP port  

  public static void main(String args[]) {
   
    // The server is listening to port number 5300
    // Creating the UDP server

    // Creating the server
    DatagramSocket server = null;

    try {
      server = new DatagramSocket(port);
      System.out.println("Created UDP Server on port" + port);
    } catch (IOException e) {
      System.err.printf("Unable to create UDP server, error: %s", e);
      System.exit(1);
    }
   
    // Initializing an empty packet to receive the query from a client
    try {
      byte[] receiveData = new byte[1024];  // Buffer for the UDP packet
      DatagramPacket senderPacket = new DatagramPacket(receiveData, receiveData.length);

      // Checks if we received the blocklist as command-line argument
      boolean sites = false;
      HashSet<String> blocklist = new HashSet<String>();
      if (args.length != 0) {
        Scanner reader = new Scanner(new File(args[0]));
        while (reader.hasNext()) {
          blocklist.add(reader.next().trim());
        }
        sites = true;
      }

      // Server is in the running state 
      while (true) {
        // Datagram has the UDP packets, and the server is getting info on the port 
        server.receive(senderPacket);
        InetAddress clientIP = senderPacket.getAddress();
        int Port = senderPacket.getPort();
        boolean blockQueries = false;

        // Checks if the query for the given website is in the block list 
        if (sites) {
          String queryname = getQuery(senderPacket);
          blockQueries = blocklist.contains(queryname);
        }
 
        // Request is being iteratively solved, providing A type Records, given the requested site isn't present in the block list
        if (!blockQueries) {

          // Random root server reply
          randomrootserver = RootServer(); // getting the query from random root server
          senderPacket.setAddress(InetAddress.getByName(randomrootserver + ".root-servers.net"));
          senderPacket.setPort(53);
          server.send(senderPacket);

          // Getting a reply from an authority or a root server 
          byte[] Buffer = new byte[4096];
          DatagramPacket receivePacket = new DatagramPacket(Buffer, Buffer.length);
          server.receive(receivePacket);

          // Getting the authority, Error, or Answer 
          int[] array = ErrorAuthority(receivePacket);
          int err = array[0];
          int answer = array[1];
          int authCount = array[2];

          // While there is no answer - Gets the next authority (to ask)
          while ((err == 0) && (answer == 0) && (authCount > 0)) {

            // Extract the next authority name server to ask; And asks the query
            String authName = AuthorityRR(receivePacket);
            senderPacket.setAddress(InetAddress.getByName(authName));
            senderPacket.setPort(53);
            server.send(senderPacket);

            // getting packet from authority or root server in the reply
            server.receive(receivePacket);
            array = ErrorAuthority(receivePacket);
            err = array[0];
            answer = array[1];
            authCount = array[2];

          }
          // setting of the flags 
          receivePacket.getData()[2] = (byte) 0b10000001; // switching ON the flags QR, RD
          byte t = (byte) ((receivePacket.getData()[3] << 4) >>> 4); // Switching OFF RA, Z
          receivePacket.getData()[3] = (byte) (0b10000000 | t); // Switching ON RA

          // Sending the answer back to the client
          receivePacket.setAddress(clientIP);
          receivePacket.setPort(Port);
          server.send(receivePacket);

        } else {  // Seting the flags for the query; if it matches the sites of the blocklist file
          senderPacket.getData()[2] = (byte) 0b10000001; // switching ON QR, RD
          senderPacket.getData()[3] = (byte) (0b10000011); // switching ON RA , Rcode = 3
          senderPacket.setAddress(clientIP);
          senderPacket.setPort(Port);
          server.send(senderPacket);
        }
      }
    } catch (IOException e) {
      System.err.printf("Error creating a UDP server, unable to establish a connection because: %s", e);
    }
  }

  // Extracting error, answer, auth counters from packet p
  public static int[] ErrorAuthority(DatagramPacket packet) {
    int[] a = new int[3];

    // Error count
    a[0] = packet.getData()[3];
    a[0] = (a[0] << 28) >>> 28;

    // answerCount
    int buffnum6 = packet.getData()[6];
    int buffnum7 = packet.getData()[7];
    buffnum6 = (buffnum6 << 24) >>> 16;
    buffnum7 = (buffnum7 << 24) >>> 24;
    a[1] = buffnum6 | buffnum7;

    // authroityCount
    int buffnum8 = packet.getData()[8];
    int buffnum9 = packet.getData()[9];

    buffnum8 = (buffnum8 << 24) >>> 16;
    buffnum9 = (buffnum9 << 24) >>> 24;
    a[2] = buffnum8 | buffnum9;

    return a;
  }

  // Getting the name of the authority from the authority packet (resource records)
  public static String AuthorityRR(DatagramPacket packet) {
    String authority = "";
    int k = 12;

    // The start of the question section
    while (packet.getData()[k] != 0) {

      if ((packet.getData()[k] & ref) == ref) {
        k++;
        break;
      }

      k++;

    }

    k += 5;

    // Initializing the authority 
    while (packet.getData()[k] != 0) {

      if ((packet.getData()[k] & ref) == ref) {
        k++;
        break;
      }

      k++;

    }

    k += 11;
    byte bytes = packet.getData()[k];

    if ((packet.getData()[k] & ref) == ref) { // Looking for the 'starting' bytes
      k = Referenceloc(packet, k);
      bytes = packet.getData()[k];
    }

    // Continued w/reading
    while (packet.getData()[k] != 0) {

      for (int j = 0; j < bytes; j++) {
        k++;
        authority = authority + (char) (packet.getData()[k]);
      }

      authority = authority + ".";
      k++;
      bytes = packet.getData()[k];

      // Checks if we are on a reference byte
      if ((packet.getData()[k] & ref) == ref) {
        k = Referenceloc(packet, k);
        bytes = packet.getData()[k];
      }
    }

    authority = authority.substring(0, authority.length() - 1);

    return authority;
  }

  // Looking for the offset in the packet for the reading address
  public static int Referenceloc(DatagramPacket packet, int i) {
    
    byte bytes = packet.getData()[i];
    int curByte = (byte) (bytes & 0b00111111);
    int nex = packet.getData()[i + 1];
    nex = (nex << 24) >>> 24;
    curByte = (curByte << 24) >>> 24;
    int r = (curByte << 8) | nex;

    return r;
  }

  // 'Random' root server
  public static char RootServer() {
    return (char) ((Math.random() * (110 - 97)) + 97);
  }

  // Extracting the query 
  public static String getQuery(DatagramPacket packet) {
    String q = "";
    int i = 12;

    byte byteToRead = packet.getData()[i];

    if ((packet.getData()[i] & ref) == ref) {
      i = Referenceloc(packet, i);
      byteToRead = packet.getData()[i];
    }

    while (packet.getData()[i] != 0) {

      for (int j = 0; j < byteToRead; j++) {
        i++;
        q = q + (char) (packet.getData()[i]);
      }

      q = q + ".";
      i++;

      byteToRead = packet.getData()[i];

      // Checking for the reference byte
      if ((packet.getData()[i] & ref) == ref) {
        i = Referenceloc(packet, i);
        byteToRead = packet.getData()[i];
      }
    }

    q = q.substring(0, q.length() - 1);

    return q;
  }

}
