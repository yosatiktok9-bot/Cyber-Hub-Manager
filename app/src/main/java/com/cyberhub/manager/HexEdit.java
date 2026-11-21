package com.cyberhub.manager;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Byte-level editor. Patches a fixed window in place (never resizes) with a backup and an
 * atomic publish, so a failed write leaves the original untouched. */
public final class HexEdit {
 public static final int WINDOW=64*1024;
 private final File work;private File file;private long length;private long offset;private boolean readOnly;

 HexEdit(File work){this.work=work;work.mkdirs();}

 public JSONObject open(File f,long at,boolean ro)throws Exception{
  if(!f.isFile())throw new IOException("File not found");
  file=f;length=f.length();readOnly=ro;offset=Math.max(0,Math.min(at,length));
  return window();
 }

 private JSONObject window()throws Exception{
  int size=(int)Math.min(WINDOW,length-offset);
  byte[] data=new byte[Math.max(0,size)];
  try(RandomAccessFile in=new RandomAccessFile(file,"r")){in.seek(offset);in.readFully(data);}
  return new JSONObject().put("offset",offset).put("length",length).put("window",WINDOW).put("readonly",readOnly)
    .put("name",file.getName()).put("path",file.getPath()).put("bytes",Base64.getEncoder().encodeToString(data));
 }

 /** Re-open a different window of the already-opened file. */
 public JSONObject page(long at)throws Exception{
  if(file==null)throw new IOException("Open a file in the hex editor first");
  offset=Math.max(0,Math.min(at,length));
  return window();
 }

 private static byte[] decode(String s,long max)throws IOException{
  byte[] b;try{b=Base64.getDecoder().decode(s==null?"":s);}catch(IllegalArgumentException e){throw new IOException("Invalid hex data");}
  if(b.length>max)throw new IOException("Patch is too large");
  return b;
 }

 /** In-place overwrite of [at, at+bytes) with a .bak and atomic publish. No resize allowed. */
 public JSONObject save(long at,byte[] bytes)throws Exception{
  if(file==null)throw new IOException("Open a file in the hex editor first");
  if(readOnly)throw new IOException("This source is read-only. Use Save a copy.");
  if(bytes.length==0)throw new IOException("Nothing to write");
  if(at<0||at+bytes.length>length)throw new IOException("Patch must stay inside the file (no resize). File is "+length+" bytes.");
  File parent=file.getAbsoluteFile().getParentFile();
  File temp=File.createTempFile(".hex-",".tmp",parent);
  try{
   Files.copy(file.toPath(),temp.toPath(),StandardCopyOption.REPLACE_EXISTING);
   try(RandomAccessFile out=new RandomAccessFile(temp,"rw")){out.seek(at);out.write(bytes);out.getFD().sync();}
   Files.copy(file.toPath(),new File(file+".bak").toPath(),StandardCopyOption.REPLACE_EXISTING);
   if(file.length()!=length)throw new IOException("File changed externally; reopen it");
   FileOps.replace(temp,file);
  }finally{temp.delete();}
  length=file.length();offset=at;
  return window().put("sha256",FileOps.sha256(file)).put("saved",true);
 }

 /** Write a patched copy to a destination (works for read-only sources and archive entries). */
 public JSONObject saveAs(File destination,long at,byte[] bytes)throws Exception{
  if(file==null)throw new IOException("Open a file in the hex editor first");
  if(destination.exists())throw new IOException("Destination already exists");
  if(bytes.length==0)throw new IOException("Nothing to write");
  byte[] whole=FileOps.read(file,FileOps.MAX_EXTRACT);
  if(at<0||at+bytes.length>whole.length)throw new IOException("Patch must stay inside the file (no resize). File is "+whole.length+" bytes.");
  byte[] out=whole.clone();System.arraycopy(bytes,0,out,(int)at,bytes.length);
  FileOps.writeAtomic(destination,out,false);
  return new JSONObject().put("path",destination.getPath()).put("sha256",FileOps.sha256(destination)).put("saved",true);
 }

 // ---- convenience wrappers used by DataEngine ----
 public JSONObject open(File f,long at)throws Exception{return open(f,at,false);}
 public JSONObject openReadOnly(File f,long at)throws Exception{return open(f,at,true);}
 public JSONObject save(long at,String base64)throws Exception{return save(at,decode(base64,FileOps.MAX_EXTRACT));}
 public JSONObject saveAs(File destination,long at,String base64)throws Exception{return saveAs(destination,at,decode(base64,FileOps.MAX_EXTRACT));}
}
