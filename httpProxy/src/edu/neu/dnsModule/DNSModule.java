package edu.neu.dnsModule;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

public class DNSModule {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		int port = 5266;
		String data = "www.google.com";
		
		try {
			DatagramSocket dgSocket=new DatagramSocket(port);
			InetAddress IPAddress = InetAddress.getByName("localhost");
			byte[] sendData = new byte[1024];
		    byte[] receiveData = new byte[50];
		    
		    sendData=data.getBytes();
		    
		    DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, 5265);
		    dgSocket.send(sendPacket);
		    
		    DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
		    dgSocket.receive(receivePacket);
		    
		    String modifiedSentence = new String(receivePacket.getData());
		    System.out.println("FROM SERVER:" + modifiedSentence);
		    dgSocket.close();
			
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}

	}

}
