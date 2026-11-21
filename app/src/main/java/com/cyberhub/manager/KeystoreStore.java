package com.cyberhub.manager;

import android.content.*;import java.io.*;import java.nio.charset.StandardCharsets;
import java.security.*;import java.security.cert.Certificate;import java.security.cert.X509Certificate;
import java.util.*;import org.json.*;

/** Imported signing keystores, kept in app-private storage and loaded for apksig.
 * Password material lives in this app's private preferences, Base64-wrapped only to
 * avoid casual plaintext reads. It is not hardware-backed encryption: anyone able to
 * read this app's private data can recover the key. The original file is never moved. */
public final class KeystoreStore {
 static final String[] TYPES={"PKCS12","JKS","BKS","BCPKCS12"};
 final MainActivity activity;final File dir;final SharedPreferences prefs;
 KeystoreStore(MainActivity a){activity=a;dir=new File(a.getFilesDir(),"keys");dir.mkdirs();prefs=a.getPreferences(0);}

 static String clean(String name)throws IOException{
  if(name==null)throw new IOException("Enter a keystore name");
  String n=name.trim();
  if(n.isEmpty()||n.length()>60||!n.matches("[A-Za-z0-9 ._-]+")||n.equals(".")||n.equals(".."))throw new IOException("Use 1-60 letters, digits, space, dot, dash or underscore");
  return n;
 }
 File file(String name)throws IOException{return FileOps.child(dir,clean(name)+".keystore");}

 private List<String> index(){try{JSONArray a=new JSONArray(prefs.getString("ks-index","[]"));List<String> out=new ArrayList<>();for(int i=0;i<a.length();i++)out.add(a.getString(i));return out;}catch(Exception e){return new ArrayList<>();}}
 private void saveIndex(List<String> names){prefs.edit().putString("ks-index",new JSONArray(names).toString()).apply();}
 private JSONObject meta(String name){try{String raw=prefs.getString("ks:"+name,null);if(raw==null)return null;return new JSONObject(raw);}catch(Exception e){return null;}}
 private static String wrap(String s){return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));}
 private static String unwrap(String s){try{return s==null?"":new String(Base64.getDecoder().decode(s),StandardCharsets.UTF_8);}catch(Exception e){return "";}}

 public boolean has(String name){return meta(name)!=null;}
 public String defaultName(){return prefs.getString("ks-default","");}
 void setDefault(String name){prefs.edit().putString("ks-default",name==null?"":name).apply();}

 public JSONArray list()throws Exception{
  JSONArray out=new JSONArray();
  for(String name:index()){JSONObject m=meta(name);if(m!=null)out.put(info(m));}
  return out;
 }

 public JSONObject info(String name)throws Exception{
  JSONObject m=meta(name);if(m==null)throw new IOException("Keystore not found: "+clean(name));
  return info(m);
 }

 private JSONObject info(JSONObject m)throws Exception{
  JSONObject out=new JSONObject().put("name",m.getString("name")).put("type",m.getString("type")).put("alias",m.getString("alias")).put("created",m.optLong("created")).put("default",m.getString("name").equals(defaultName()));
  File f=file(m.getString("name"));
  if(!f.isFile())return out.put("sha256","-");
  out.put("size",f.length());
  try{out.put("sha256",FileOps.sha256(f));}catch(Exception e){out.put("sha256","-");}
  try{
   KeyStore ks=KeyStore.getInstance(m.getString("type"));
   try(InputStream in=new FileInputStream(f)){ks.load(in,unwrap(m.getString("storePassword")).toCharArray());}
   Certificate c=ks.getCertificate(m.getString("alias"));
   if(c instanceof X509Certificate){X509Certificate x=(X509Certificate)c;
    out.put("subject",x.getSubjectX500Principal().getName()).put("expires",x.getNotAfter().getTime()).put("algorithm",x.getPublicKey().getAlgorithm());
    out.put("issuer",x.getIssuerX500Principal().getName());
   }
  }catch(Exception ignore){}
  return out;
 }

 /** Verifies the file loads, records the key alias, then copies it into private storage. */
 public JSONObject importKey(String path,String storePassword,String keyPassword,String name)throws Exception{
  String id=clean(name);
  File src=new File(path);if(!src.isFile())throw new IOException("Keystore file not found");
  byte[] data=FileOps.read(src,8L*1024*1024);
  String storePw=storePassword==null?"":storePassword;
  String keyPw=(keyPassword==null||keyPassword.isEmpty())?storePw:keyPassword;
  char[] store=storePw.toCharArray(),keyPass=keyPw.toCharArray();
  String[] found=null;
  for(String type:TYPES){
   try{
    KeyStore ks=KeyStore.getInstance(type);
    ks.load(new ByteArrayInputStream(data),store);
    for(Enumeration<String> e=ks.aliases();e.hasMoreElements();){
     String alias=e.nextElement();if(!ks.isKeyEntry(alias))continue;
     try{Key k=ks.getKey(alias,keyPass);if(k instanceof PrivateKey){found=new String[]{type,alias};break;}}catch(Exception ignore){}
    }
   }catch(Exception ignore){/* try the next provider */}
   if(found!=null)break;
  }
  if(found==null)throw new IOException("Could not open this keystore. Check the password. Android does not read Sun JKS directly: convert with keytool -importkeystore -deststoretype PKCS12.");
  File target=file(id);
  FileOps.writeAtomic(target,data,false);
  JSONObject m=new JSONObject().put("name",id).put("type",found[0]).put("alias",found[1])
    .put("storePassword",wrap(storePw)).put("keyPassword",wrap(keyPw)).put("created",System.currentTimeMillis());
  prefs.edit().putString("ks:"+id,m.toString()).apply();
  List<String> names=index();if(!names.contains(id)){names.add(id);saveIndex(names);}
  if(defaultName().isEmpty())setDefault(id);
  return info(m);
 }

 /** Loads an imported keystore and detaches its key material for signing. */
 public ApkSigning.Credential credential(String name)throws Exception{
  JSONObject m=meta(name);if(m==null)throw new IOException("Keystore not found: "+name);
  File f=file(name);if(!f.isFile())throw new IOException("Keystore file is missing: "+name);
  String type=m.getString("type"),alias=m.getString("alias");
  KeyStore ks=KeyStore.getInstance(type);
  try(InputStream in=new FileInputStream(f)){ks.load(in,unwrap(m.getString("storePassword")).toCharArray());}
  char[] keyPass;
  try{keyPass=unwrap(m.getString("keyPassword")).toCharArray();if(ks.getKey(alias,keyPass)==null)keyPass=unwrap(m.getString("storePassword")).toCharArray();}
  catch(Exception first){keyPass=unwrap(m.getString("storePassword")).toCharArray();}
  return ApkSigning.from(ks,alias,keyPass,alias);
 }

 public boolean delete(String name)throws Exception{
  String id=clean(name);
  File f=file(id);if(f.exists())FileOps.deleteTree(f);
  prefs.edit().remove("ks:"+id).apply();
  List<String> names=index();names.remove(id);saveIndex(names);
  if(defaultName().equals(id))setDefault(names.isEmpty()?"":names.get(0));
  return true;
 }
}
