package com.cyberhub.manager;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import com.android.apksig.*;

/** Publishes an APK only after all requested signature schemes verify. */
public final class ApkSigning {
 private ApkSigning() {}

 /** Signing material detached from any KeyStore implementation. */
 public static final class Credential {
  public final PrivateKey key;public final List<X509Certificate> chain;public final String label;
  public Credential(PrivateKey key,List<X509Certificate> chain,String label){this.key=key;this.chain=chain;this.label=label;}
 }

 /** Signs with the bundled development key (kept for the built-in default). */
 public static void sign(File source,File destination,InputStream keyStream)throws Exception {
  sign(source,destination,fromStream(keyStream));
 }

 /** Builds a credential from the bundled development PKCS12 stream. */
 public static Credential fromStream(InputStream keyStream)throws Exception {
  KeyStore store=KeyStore.getInstance("PKCS12");
  char[] password="cyberhub-development".toCharArray();
  store.load(keyStream,password);
  String alias=store.aliases().nextElement();
  return from(store,alias,password,"CyberHubDevelopment");
 }

 /** Builds a credential from a loaded keystore and key alias. */
 public static Credential from(KeyStore store,String alias,char[] password,String label)throws Exception {
  PrivateKey key=(PrivateKey)store.getKey(alias,password);
  List<X509Certificate> chain=certificates(store,alias);
  if(key==null||chain.isEmpty())throw new IOException("This keystore has no usable private key for signing");
  return new Credential(key,chain,label==null||label.isEmpty()?alias:label);
 }

 static List<X509Certificate> certificates(KeyStore store,String alias)throws Exception {
  Certificate[] raw=store.getCertificateChain(alias);
  if(raw==null||raw.length==0){Certificate single=store.getCertificate(alias);if(single!=null)raw=new Certificate[]{single};}
  List<X509Certificate> chain=new ArrayList<>();
  if(raw!=null)for(Certificate c:raw)if(c instanceof X509Certificate)chain.add((X509Certificate)c);
  return chain;
 }

 /** Signs with a prepared credential: V1 + V2 + V3, mandatory verification, atomic publish. */
 public static void sign(File source,File destination,Credential credential)throws Exception {
  if(destination.exists())throw new IOException("Signed output already exists");
  File parent=destination.getAbsoluteFile().getParentFile();
  File temporary=File.createTempFile(".verified-sign-",".apk",parent);
  try {
   ApkSigner.SignerConfig signer=new ApkSigner.SignerConfig.Builder(credential.label,credential.key,credential.chain).build();
   new ApkSigner.Builder(Collections.singletonList(signer)).setInputApk(source).setOutputApk(temporary).setV1SigningEnabled(true).setV2SigningEnabled(true).setV3SigningEnabled(true).setMinSdkVersion(21).build().sign();
   ApkVerifier.Result result=new ApkVerifier.Builder(temporary).setMinCheckedPlatformVersion(21).build().verify();
   if(!result.isVerified()||!result.isVerifiedUsingV1Scheme()||!result.isVerifiedUsingV2Scheme()||!result.isVerifiedUsingV3Scheme())throw new IOException("APK signature verification failed: "+result.getErrors());
   if(destination.exists())throw new IOException("Output was created by another operation");
   FileOps.replace(temporary,destination);
  }finally{temporary.delete();}
 }
}
