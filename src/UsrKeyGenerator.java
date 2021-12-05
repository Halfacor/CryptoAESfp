import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

// https://stackoverflow.com/questions/5175728/how-to-get-the-current-date-time-in-java
public class UsrKeyGenerator {
    public static File generateKey(String parentDir) throws IOException {
        File pd = new File(parentDir);
        if (!pd.exists()) {
            System.out.println("Given dir not exist!");
            return null;
        } else if (!pd.isDirectory()) {
            System.out.println("You gave a file instead of dir!");
            return null;
        }
        String pathName = parentDir + "/" + "Key_" + System.currentTimeMillis() + ".txt";
        File keyFile = new File(pathName);
        byte[] key = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(key);

        FileOutputStream fos = new FileOutputStream(keyFile);
        fos.write(key);
        fos.close();
        return keyFile;
    }
}
