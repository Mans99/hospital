package client;

import java.net.*;
import java.io.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.security.cert.*;

/*
 * This example shows how to set up a key manager to perform client
 * authentication.
 *
 * This program assumes that the client is not inside a firewall.
 * The application can be modified to connect to a server outside
 * the firewall by following SSLSocketClientWithTunneling.java.
 */

public class Client {
	
  public static void main(String[] args) throws Exception {
    String host = null;
    int port = -1;
    for (int i = 0; i < args.length; i++) {
      System.out.println("args[" + i + "] = " + args[i]);
    }
    if (args.length < 2) {
      System.out.println("USAGE: java client host port");
      System.exit(-1);
    }
    
    try { /* get input parameters */
      host = args[0];
      port = Integer.parseInt(args[1]);
    } catch (IllegalArgumentException e) {
      System.out.println("USAGE: java client host port");
      System.exit(-1);
    }
    
    try {
      SSLSocketFactory factory = null;
      try {
        char[] password = "password".toCharArray(); // Bör hämta lösenordet på annat sätt
        												// Scanner?
        												// Kryptering
        KeyStore ks = KeyStore.getInstance("JKS"); 
        KeyStore ts = KeyStore.getInstance("JKS"); 
        
        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        
        
        
        // keystore password (storepass)
        ks.load(new FileInputStream("clientkeystore"), password); //Samma sak här
        // truststore password (storepass);
        ts.load(new FileInputStream("clienttruststore"), password); // Samma sak här
        kmf.init(ks, password); // user password (keypass)
        tmf.init(ts); // keystore can be used as truststore here
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        factory = ctx.getSocketFactory();
      } catch (Exception e) {
        throw new IOException(e.getMessage());
      }
      SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
      System.out.println("\nsocket before handshake:\n" + socket + "\n");


      
      
      // Funktion för hantering av request objekt
      		// Switch case för de olika alternativen, read, write etc
      			// FileChannel, fileoutputstream, filechannel()
      
      
      
      socket.startHandshake();
      SSLSession session = socket.getSession();
      Certificate[] cert = session.getPeerCertificates();
      String subject = ((X509Certificate) cert[0]).getSubjectX500Principal().getName();
      System.out.println("certificate name (subject DN field) on certificate received from server:\n" + subject + "\n");
      System.out.println("socket after handshake:\n" + socket + "\n");
      System.out.println("secure connection established\n\n");

      BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
      PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
      BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      String msg;
      for (;;) {
        System.out.print(">"); 
        // Ha kontroll på kommandon, snacka med server och ACL
        msg = read.readLine();
        if (msg.equalsIgnoreCase("quit")) {
          break;
        }
        System.out.print("sending '" + msg + "' to server...");
        out.println(msg);
        out.flush(); // 
        System.out.println("done");
        System.out.println("received '" + in.readLine() + "' from server\n");
      }
      in.close();
      out.close();
      read.close();
      socket.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
