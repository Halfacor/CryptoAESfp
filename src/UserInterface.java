import hongyzeng.cbc.CBCMachine;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Get User Input from System.in
 * ask for mode: Enc / Dec
 * ask for textFile
 * check validity of the textFile: length (Dec must be multiple of 128 bits)
 * then ask for keyFile, provide option to generate one if current mode is Enc, output location
 * check validity of the keyFile: 128 bits
 * ask for IV file, provide option to generate one if in Enc, output location
 * check validity of the keyFile: 128 bits
 * read files and do AES with CBC
 * return output file location
 */

// https://www.geeksforgeeks.org/ways-to-read-input-from-console-in-java/
public class UserInterface {
    private boolean aesMode; // true when decrypting
    private BufferedReader consoleReader;

    public UserInterface() {
        aesMode = false;
        consoleReader = new BufferedReader(
                new InputStreamReader(System.in));
    }


    public void start() throws IOException {
        System.out.println("Starting Service!");
        askForMode();
        System.out.println(aesMode);
        File textFile = askForTextFile();
        File keyFile = askForKeyFile();
        File ivFile = askForIVFile();
        File outputFile = null;
        while (outputFile == null) {
            System.out.print("Give me the absolute path to the parent dir where you want the output to be: ");
            File pd = new File(consoleReader.readLine());
            if (!pd.exists()) {
                System.out.println("Given dir not exist!");
                continue;
            } else if (!pd.isDirectory()) {
                System.out.println("You gave a file instead of dir!");
                continue;
            }
            outputFile = new File(pd.getAbsolutePath() + "\\" + (aesMode ? "Dec" : "Enc") +"Output_" + System.currentTimeMillis() + ".txt");
        }
        CBCMachine cbcMachine = new CBCMachine(textFile, keyFile, ivFile, aesMode, outputFile);
        cbcMachine.start();
        System.out.println("Job Done!");
    }


    private void askForMode() throws IOException {
        System.out.print("Choose your Mode (Enc/Dec): ");
        String mode = consoleReader.readLine();
        if (mode.equals("Dec")) {
            aesMode = true;
        }
    }


    private File askForTextFile() throws IOException {
        File textFile = null;
        boolean valid = false;
        while (!valid) {
            System.out.print("Give me your input text File location: ");
            textFile = new File(consoleReader.readLine());
            if (!textFile.exists()) {
                System.out.println("File not exists!");
                continue;
            } else if (!textFile.isFile()) {
                System.out.println("Not a File!");
                continue;
            } else if (aesMode && textFile.length() % 16 != 0) {
                System.out.println("Decryption need length with a multiple of 16 bytes!");
                continue;
            }

            valid = true;
        }
        return textFile;
    }


    private File askForKeyFile() throws IOException {
        File keyFile = null;
        boolean valid = false;
        while (!valid) {
            if (!aesMode) {
                System.out.print("Do you need me to generate key for you? (Y/N): ");
                boolean generateForUser = consoleReader.readLine().equals("Y");
                if (generateForUser) {
                    System.out.println("Ok, I'll generate one for you!");
                    System.out.print("Give me the absolute path to the parent dir: ");
                    keyFile = UsrKeyGenerator.generateKey(consoleReader.readLine());
                    if (keyFile == null) {
                        continue;
                    }
                } else {
                    System.out.print("Give me the keyFile location: ");
                    keyFile = new File(consoleReader.readLine());
                }
            } else {
                System.out.print("Give me the keyFile location: ");
                keyFile = new File(consoleReader.readLine());
            }

            if (!keyFile.exists()) {
                System.out.println("KeyFile not exists!");
                continue;
            } else if (!keyFile.isFile()) {
                System.out.println("Not a File!");
                continue;
            } else if (keyFile.length() != 16) {
                System.out.println("KeyFile needs to be 16 bytes!");
                continue;
            }
            valid = true;
        }
        return keyFile;
    }


    private File askForIVFile() throws IOException {
        File ivFile = null;
        boolean valid = false;
        while (!valid) {
            if (!aesMode) {
                System.out.print("Do you need me to generate IV for you? (Y/N): ");
                boolean generateForUser = consoleReader.readLine().equals("Y");
                if (generateForUser) {
                    System.out.println("Ok, I'll generate one for you!");
                    System.out.print("Give me the absolute path to the parent dir: ");
                    ivFile = UsrIVGenerator.generateIV(consoleReader.readLine());
                    if (ivFile == null) {
                        continue;
                    }
                } else {
                    System.out.print("Give me the IVFile location: ");
                    ivFile = new File(consoleReader.readLine());
                }
            } else {
                System.out.print("Give me the IVFile location: ");
                ivFile = new File(consoleReader.readLine());
            }

            if (!ivFile.exists()) {
                System.out.println("IVFile not exists!");
                continue;
            } else if (!ivFile.isFile()) {
                System.out.println("Not a File!");
                continue;
            } else if (ivFile.length() != 16) {
                System.out.println("IVFile needs to be 16 bytes!");
                continue;
            }
            valid = true;
        }
        return ivFile;
    }
}
