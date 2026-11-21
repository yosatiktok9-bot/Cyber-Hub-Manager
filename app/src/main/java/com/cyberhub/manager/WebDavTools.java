package com.cyberhub.manager;

import java.io.*;import java.net.*;import java.nio.charset.StandardCharsets;import java.util.*;
import javax.xml.parsers.*;import org.json.*;import org.w3c.dom.*;

/** Minimal WebDAV (RFC 4918) client: PROPFIND listing, GET download, PUT upload.
 * Built on java.net only, so it adds no bundled jars. Basic auth over HTTP(S). */
public final class WebDavTools {
 private static final String BODY="<?xml version=\"1.0\" encoding=\"utf-8\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/><d:displayname/></d:prop></d:propfind>";

 private static String base(JSONObject a)throws IOException{
  String host=a.getString("host").trim();
  if(!host.startsWith("http://")&&!host.startsWith("https://")){boolean tls=a.optBoolean("tls",true);int port=a.optInt("port",0);host=(tls?"https":"http")+"://"+host+(port>0?":"+port:"");}
  while(host.endsWith("/"))host=host.substring(0,host.length()-1);
  try{new URL(host);}catch(MalformedURLException e){throw new IOException("Enter a valid WebDAV URL, e.g. https://server/dav");}
  return host;
 }
 private static String encode(String path){
  if(path==null)path="";
  StringBuilder b=new StringBuilder();
  for(String part:path.split("/")){if(part.isEmpty())continue;try{b.append('/').append(URLEncoder.encode(part,StandardCharsets.UTF_8.name()).replace("+","%20"));}catch(UnsupportedEncodingException e){b.append('/').append(part);}}
  return b.length()==0?"/":b.toString();
 }
 private static HttpURLConnection open(String url,JSONObject a,String method)throws IOException{
  HttpURLConnection c=(HttpURLConnection)new URL(url).openConnection();
  c.setConnectTimeout(15000);c.setReadTimeout(60000);c.setInstanceFollowRedirects(true);
  String user=a.optString("user");
  if(!user.isEmpty())c.setRequestProperty("Authorization","Basic "+Base64.getEncoder().encodeToString((user+":"+a.optString("password")).getBytes(StandardCharsets.UTF_8)));
  c.setRequestMethod(method);return c;
 }
 private static void expect(HttpURLConnection c,int... ok)throws IOException{
  int code=c.getResponseCode();
  for(int k:ok)if(code==k)return;
  String message="WebDAV server returned HTTP "+code;
  try(InputStream in=c.getErrorStream()){if(in!=null){String body=new String(FileOps.bytes(in,4096),StandardCharsets.UTF_8).trim();if(!body.isEmpty())message+=": "+body.replaceAll("<[^>]+>"," ").replaceAll("\\s+"," ").trim();}}
  throw new IOException(message);
 }
 private static String name(String href,String base){
  String path;
  try{path=new URI(href).getPath();}catch(Exception e){path=href;}
  if(path==null||path.isEmpty())path=href;
  if(path.endsWith("/"))path=path.substring(0,path.length()-1);
  int slash=path.lastIndexOf('/');
  return slash>=0?path.substring(slash+1):path;
 }

 public static Object call(JSONObject a)throws Exception{
  String base=base(a),op=a.optString("op","list"),path=a.optString("remote","");
  if(op.equals("list")){
   HttpURLConnection c=open(base+encode(path),a,"PROPFIND");
   c.setRequestProperty("Depth","1");c.setRequestProperty("Content-Type","application/xml; charset=utf-8");c.setDoOutput(true);
   try(OutputStream out=c.getOutputStream()){out.write(BODY.getBytes(StandardCharsets.UTF_8));}
   expect(c,207,200);
   DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();factory.setNamespaceAware(true);
   try{factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);}catch(Exception ignore){}
   Document doc;try(InputStream in=c.getInputStream()){doc=factory.newDocumentBuilder().parse(in);}
   JSONArray arr=new JSONArray();NodeList responses=doc.getElementsByTagNameNS("DAV:","response");
   for(int i=0;i<responses.getLength();i++){
    Element r=(Element)responses.item(i);String href=text(r,"href");
    JSONObject entry=new JSONObject();
    NodeList types=r.getElementsByTagNameNS("DAV:","collection");boolean dir=types.getLength()>0;
    String nm=name(href,base);if(nm.isEmpty())continue;
    long size=0;try{size=Long.parseLong(text(r,"getcontentlength"));}catch(Exception ignore){}
    entry.put("name",nm).put("dir",dir).put("size",size);
    String modified=text(r,"getlastmodified");if(!modified.isEmpty())entry.put("modified",modified);
    arr.put(entry);
   }
   return arr;
  }
  if(op.equals("download")){
   File dst=new File(a.getString("local"));if(dst.exists())throw new IOException("Local file already exists");
   HttpURLConnection c=open(base+encode(path),a,"GET");expect(c,200);
   try(InputStream in=c.getInputStream();OutputStream out=new FileOutputStream(dst)){FileOps.copy(in,out,FileOps.MAX_EXTRACT);}
   catch(Exception e){dst.delete();throw e;}
   return dst.getPath();
  }
  if(op.equals("upload")){
   File src=new File(a.getString("local"));if(!src.isFile())throw new IOException("Local file not found");
   HttpURLConnection c=open(base+encode(path),a,"PUT");c.setDoOutput(true);c.setRequestProperty("Content-Type","application/octet-stream");
   c.setFixedLengthStreamingMode(src.length());
   try(InputStream in=new FileInputStream(src);OutputStream out=c.getOutputStream()){FileOps.copy(in,out,FileOps.MAX_EXTRACT);}
   expect(c,200,201,204);
   return true;
  }
  throw new IOException("Unknown WebDAV operation");
 }
 private static String text(Element parent,String local){
  NodeList list=parent.getElementsByTagNameNS("DAV:",local);
  if(list.getLength()==0)return "";
  String value=list.item(0).getTextContent();
  return value==null?"":value.trim();
 }
}
