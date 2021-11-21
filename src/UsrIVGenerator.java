import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

public class UsrIVGenerator {
    public static File generateIV(String parentDir) throws IOException {
        File pd = new File(parentDir);
        if (!pd.exists()) {
            System.out.println("Given dir not exist!");
            return null;
        } else if (!pd.isDirectory()) {
            System.out.println("You gave a file instead of dir!");
            return null;
        }
        String pathName = parentDir + "\\" + "IV_" + System.currentTimeMillis() + ".txt";
        File keyFile = new File(pathName);
        byte[] IV = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(IV);

        FileOutputStream fos = new FileOutputStream(keyFile);
        fos.write(IV);
        fos.close();
        return keyFile;
    }
}
