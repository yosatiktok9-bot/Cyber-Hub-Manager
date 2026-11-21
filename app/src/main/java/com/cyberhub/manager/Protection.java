package com.cyberhub.manager;

import java.io.*;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.zip.*;
import org.json.*;
import com.android.apksig.ApkVerifier;

/** Best-effort packer/protection fingerprint plus real signer-certificate details.
 * Heuristics only: a marker match means "looks like", never a guarantee. */
public final class Protection {
 private Protection(){}
 // {label, marker, marker, ...} matched against archive entry names (case-insensitive).
 private static final Object[][] PACKERS={
  {"360 Jiagu (360加固)","libjiagu","libjiagu_art","libjiagu_x86","libjiagu_a64"},
  {"Tencent Legu (腾讯乐固)","libshell","libtosprotection","libtxmima","libshella"},
  {"Bangcle / SecNeo (梆梆)","libsecexe","libsecmain","libdexshel","libsecneo"},
  {"Najia (娜迦)","libnagainstall","libngentity","libchaosvmp","libnqshield"},
  {"Ijiami (爱加密)","libijiami","libexecv2","libexecmain"},
  {"AliProtect (阿里加固)","libmobisec","libsgmain","libsgsecuritybody"},
  {"DexProtector","libdexprotector"},
  {"Virbox (深思)","libvboxdefender","libvmp"},
 };

 public static JSONObject inspect(File apk)throws Exception{
  JSONArray packers=new JSONArray();List<String> notes=new ArrayList<>();List<String> names=new ArrayList<>();
  int dexCount=0,libCount=0,assetDex=0;SortedSet<String> libs=new TreeSet<>();
  try(ZipFile z=new ZipFile(apk)){
   Enumeration<? extends ZipEntry> en=z.entries();
   while(en.hasMoreElements()){
    ZipEntry e=en.nextElement();if(e.isDirectory())continue;
    String name=e.getName(),lower=name.toLowerCase(Locale.ROOT);names.add(lower);
    if(name.matches("(?i)classes[0-9]*\\.dex"))dexCount++;
    else if(lower.startsWith("assets/")&&lower.endsWith(".dex"))assetDex++;
    else if(name.startsWith("lib/")&&name.endsWith(".so")){libCount++;libs.add(name.substring(name.lastIndexOf('/')+1));}
   }
  }
  Set<String> matched=new LinkedHashSet<>();
  for(Object[] row:PACKERS){
   outer:
   for(int i=1;i<row.length;i++){String marker=((String)row[i]).toLowerCase(Locale.ROOT);
    for(String n:names)if(n.contains(marker)){matched.add((String)row[0]);break outer;}
   }
  }
  for(String label:matched)packers.put(label);
  if(!matched.isEmpty())notes.add("A packer/protector signature was found. DEX names and manifest behavior may be decoys; static edits can fail at runtime.");
  else notes.add("No known packer signature found. This does not prove the APK is unprotected.");
  if(assetDex>0){packers.put("Encrypted/embedded DEX (assets)");notes.add("DEX files exist under assets/, which usually means encrypted or secondary DEX payloads.");}
  if(dexCount>1)notes.add("MultiDex: "+dexCount+" classes*.dex files.");
  if(libCount==0)notes.add("No native libraries; likely pure Java/Kotlin.");

  JSONObject signature=new JSONObject();
  try{
   ApkVerifier.Result r=new ApkVerifier.Builder(apk).build().verify();
   List<String> schemes=new ArrayList<>();
   if(r.isVerifiedUsingV1Scheme())schemes.add("V1");
   if(r.isVerifiedUsingV2Scheme())schemes.add("V2");
   if(r.isVerifiedUsingV3Scheme())schemes.add("V3");
   if(r.isVerifiedUsingV31Scheme())schemes.add("V3.1");
   signature.put("verified",r.isVerified()).put("schemes",new JSONArray(schemes));
   JSONArray signers=new JSONArray();
   List<X509Certificate> certs=r.getSignerCertificates();
   if(certs!=null)for(X509Certificate c:certs)signers.put(new JSONObject().put("subject",c.getSubjectX500Principal().getName()).put("issuer",c.getIssuerX500Principal().getName()).put("algorithm",c.getPublicKey().getAlgorithm()).put("expires",c.getNotAfter().getTime()).put("sha256",hex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()))));
   signature.put("signers",signers);
   if(signers.length()==0&&r.isVerified())signature.put("note","Verified, but signer certificates could not be read (V1-only or unusual signature).");
   if(!r.isVerified())notes.add("Signature is invalid or missing; installing it as an update will fail.");
  }catch(Exception e){signature.put("verified",false).put("error",String.valueOf(e.getMessage()));notes.add("Signature could not be checked: "+e.getMessage());}

  return new JSONObject().put("signature",signature).put("packers",packers).put("dexCount",dexCount).put("libCount",libCount).put("libs",new JSONArray(libs)).put("notes",new JSONArray(notes));
 }
 static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format("%02x",v&255));return s.toString();}
}
