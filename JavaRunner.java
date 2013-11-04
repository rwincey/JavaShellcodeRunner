/*
 * JavaRunner.java
 *
 * Created on June 14, 2013
 */

package shellcoderunner;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Locale;
import java.util.Stack;
import java.util.StringTokenizer;

/**
 *  
 * @author rwincey - borrowed functions from the java meterpreter stage for
 * resolving the java path.
 * 
 */
public class JavaRunner implements Runnable {

    private final String[] theCommand;
    protected static final String NAME_Class = JavaRunner.class.getSimpleName();
    private int exitValue = 0;
    private final StringBuilder stdOutString = new StringBuilder();
    private final StringBuilder stdErrString = new StringBuilder();
    
    //Needed for resolution
    private static final String OS_NAME = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);
    private static final String PATH_SEP = System.getProperty("path.separator");
    private static final boolean IS_AIX = "aix".equals(OS_NAME);
    private static final boolean IS_DOS = PATH_SEP.equals(";");
    private static final String JAVA_HOME = System.getProperty("java.home");
    
    //===============================================================
    /**
     *  Constructor
    */
    public JavaRunner( String[] passedCommand ) {
        theCommand = passedCommand;
    }
    
    //===============================================================
    /**
     * 
     */
    @Override
    public void run() {
        
        try {
            
            Process aProc = Runtime.getRuntime().exec(theCommand);
            OutputStream theirStdin = aProc.getOutputStream();
            try {
                theirStdin.close();
            } catch ( IOException ioe ) {
                ioe = null;
            }
            
            //Collect the data from stdout...
            final BufferedInputStream stdOutBIS = new BufferedInputStream( aProc.getInputStream() );
            Thread aThread = new Thread( new Runnable() {

                @Override
                public void run() {
                    
                    int readBytes = 0;
                    byte[] aByteArray = new byte[1000];
                    
                    while( readBytes != -1 ){
                        
                        try {
                            readBytes = stdOutBIS.read(aByteArray);
                        } catch (IOException ex) {
                        }
                        
                        //Add it to the stringbuilder
                        if( readBytes != -1){
                            
                            byte[] tempStr = Arrays.copyOf(aByteArray, readBytes);
                            stdOutString.append( new String(tempStr));
                            
                        } 
                        
                    }
                   
                    //Close the stream
                    try {
                        stdOutBIS.close();
                    } catch (IOException ex) {                    
                    }
                }
                
            });  
            aThread.start();
            
            //Collect the data from stderr...
            final BufferedInputStream stdErrIS = new BufferedInputStream( aProc.getErrorStream() );
            aThread = new Thread( new Runnable() {

                @Override
                public void run() {
                    
                    int readBytes = 0;
                    byte[] aByteArray = new byte[1000];
                    
                    while( readBytes != -1 ){
                        
                        try {
                            readBytes = stdErrIS.read(aByteArray);
                        } catch (IOException ex) {
                        }
                        
                        //Add it to the stringbuilder
                        if( readBytes != -1){
                            
                            byte[] tempStr = Arrays.copyOf(aByteArray, readBytes);
                            stdErrString.append( new String(tempStr));
                            
                        } 
                        
                    }
                    
                     //Close the stream
                    try {
                        stdErrIS.close();
                    } catch (IOException ex) {                    
                    }
                }
                
            });  
            aThread.start();
            
            exitValue = aProc.waitFor();           
            
        } catch (InterruptedException ex) {
            ex = null;
        } catch (IOException ex) {
            ex = null;
        }
        
    }
    
    //===============================================================
    /**
     *  Returns the standard output as a string.
    */
    public String getStdOut() {
        return stdOutString.toString();
    }
    
     //===============================================================
    /**
     *   Returns the standard error as a string.
    */
    public String getStdErr() {
        return stdErrString.toString();
    }

    //===============================================================
    /**
     *  Return the exit value from the run.
    */
    public int getExitValue() {
        return exitValue;
    }
    
    //=========================================================================
    /** The functions below were borrowed from Metasploit's java meterpreter stager
     *  for resolving the java path.
     */
    
    //===============================================================
    /**
     * 
     * @param paramString
     * @return 
    */
    public static String getJreExecutable(String paramString) {
        File localFile = null;
        if (IS_AIX)
            localFile = findInDir(JAVA_HOME + "/sh", paramString);
        if (localFile == null)
            localFile = findInDir(JAVA_HOME + "/bin", paramString);
        if (localFile != null)
            return localFile.getAbsolutePath();
        return addExtension(paramString);
    }

     //===============================================================
     /**
     * 
     * @param paramString
     * @return 
     */
     private static String addExtension(String paramString) {
        return paramString + (IS_DOS ? ".exe" : "");
     }

    //===============================================================
    /**
    * 
    * @param paramString1
    * @param paramString2
    * @return 
    */
    private static File findInDir(String paramString1, String paramString2) {
        File localFile1 = normalize(paramString1);
        File localFile2 = null;
        if (localFile1.exists()) {
            localFile2 = new File(localFile1, addExtension(paramString2));
            if (!localFile2.exists())
                localFile2 = null;
        }
        return localFile2;
    }

    //===============================================================
     /**
      * 
      * @param paramString
      * @return 
      */
    private static File normalize(String paramString) {
        Stack localStack = new Stack();
        String[] arrayOfString = dissect(paramString);
        localStack.push(arrayOfString[0]);
        StringTokenizer localStringTokenizer = new StringTokenizer(arrayOfString[1], File.separator);
        while (localStringTokenizer.hasMoreTokens()) {
            String localObject = localStringTokenizer.nextToken();
            if (!".".equals(localObject))
                if ("..".equals(localObject)) {
                    if (localStack.size() < 2)
                        return new File(paramString);
                    localStack.pop();
                } else {
                    localStack.push(localObject);
                }
        }
        Object localObject = new StringBuffer();
        for (int i = 0; i < localStack.size(); i++) {
            if (i > 1)
                ((StringBuffer)localObject).append(File.separatorChar);
                ((StringBuffer)localObject).append(localStack.elementAt(i));
            }
        return new File(((StringBuffer)localObject).toString());
    }

    //===============================================================
     /**
      * 
      * @param paramString
      * @return 
      */
    private static String[] dissect(String paramString){
        char c = File.separatorChar;
        paramString = paramString.replace('/', c).replace('\\', c);
        String str;
        int i = paramString.indexOf(':');
        int j;
        if ((i > 0) && (IS_DOS)) {
            j = i + 1;
            str = paramString.substring(0, j);
            char[] arrayOfChar = paramString.toCharArray();
            str = str + c;
            j = arrayOfChar[j] == c ? j + 1 : j;
            StringBuilder localStringBuffer = new StringBuilder();
            for (int k = j; k < arrayOfChar.length; k++)
                if ((arrayOfChar[k] != c) || (arrayOfChar[(k - 1)] != c))
                    localStringBuffer.append(arrayOfChar[k]);
            paramString = localStringBuffer.toString();
        } else if ((paramString.length() > 1) && (paramString.charAt(1) == c)) {
      
            j = paramString.indexOf(c, 2);
            j = paramString.indexOf(c, j + 1);
            str = j > 2 ? paramString.substring(0, j + 1) : paramString;
            paramString = paramString.substring(str.length());
        
        } else {
            str = File.separator;
            paramString = paramString.substring(1);
        }
        return new String[] { str, paramString };
    }
    

}
