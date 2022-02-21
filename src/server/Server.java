package server;

import java.io.*;
import java.net.*;
import javax.net.*;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class Server implements Runnable {
  private ServerSocket serverSocket = null;
  private static int numConnectedClients = 0;
  
  public Server(ServerSocket ss) throws IOException {
    serverSocket = ss;
    
    
    // Skapa doktorer, patienter, nurses och lägger till patienter till nurses. 
    
    
    newListener();
  }

  public void run() {
    try {
      SSLSocket socket=(SSLSocket)serverSocket.accept();
      newListener();
      SSLSession session = socket.getSession();
      Certificate[] cert = session.getPeerCertificates();
      String subject = ((X509Certificate) cert[0]).getSubjectX500Principal().getName();
      numConnectedClients++;
      System.out.println("client connected");
      System.out.println("client name (cert subject DN field): " + subject);
      System.out.println(numConnectedClients + " concurrent connection(s)\n");

      PrintWriter out = null;
      BufferedReader in = null;
      out = new PrintWriter(socket.getOutputStream(), true);
      in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

      String clientMsg = null;
      while ((clientMsg = in.readLine()) != null) {
        String rev = new StringBuilder(clientMsg).reverse().toString(); // Här händer det grejer
        System.out.println("received '" + clientMsg + "' from client"); // Titta ACL, switch case beroende på 
        System.out.print("sending '" + rev + "' to client...");				// metodanrop, open, write etc.
        out.println(rev);
        out.flush();
        System.out.println("done\n");
      }
      in.close();
      out.close();   
      socket.close();
      numConnectedClients--;   
      System.out.println("client disconnected");
      System.out.println(numConnectedClients + " concurrent connection(s)\n");
    } catch (IOException e) {
      System.out.println("Client died: " + e.getMessage());
      e.printStackTrace();
      return;
    }
  }
  
  private void newListener() { 
	  
	  (new Thread(this)).start(); 
  } // calls run()
  
	  public static void main(String args[]) {
	    System.out.println("\nServer Started\n");
	    int port = -1;
	    if (args.length >= 1) {
	      port = Integer.parseInt(args[0]);
	    }
	    String type = "TLSv1.2";
	    try {
	      ServerSocketFactory ssf = getServerSocketFactory(type);
	      ServerSocket ss = ssf.createServerSocket(port);
	      ((SSLServerSocket)ss).setNeedClientAuth(true); // enables client authentication
	      new Server(ss);
	    } catch (IOException e) {
	      System.out.println("Unable to start Server: " + e.getMessage());
	      e.printStackTrace();
	    }
	  }

  private static ServerSocketFactory getServerSocketFactory(String type) {
    if (type.equals("TLSv1.2")) {
      SSLServerSocketFactory ssf = null;
      try { // set up key manager to perform server authentication
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore ts = KeyStore.getInstance("JKS");
        char[] password = "password".toCharArray(); // Dekryptering
        // keystore password (storepass)
        ks.load(new FileInputStream("serverkeystore"), password);  // Hämta filnamn på någotsätt
        // truststore password (storepass)
        ts.load(new FileInputStream("servertruststore"), password); // Hämta filnamn på någotsätt
        kmf.init(ks, password); // certificate password (keypass)
        tmf.init(ts);  // possible to use keystore as truststore here
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        ssf = ctx.getServerSocketFactory();
        return ssf;
      } catch (Exception e) {
        e.printStackTrace();
      }
    } else {
      return ServerSocketFactory.getDefault();
    }
    return null;
  }
}
