package hongyzeng.cbc;

import java.io.*;
import hongyzeng.aes.*;

public class CBCMachine {
    private final byte[] IV;
    private final byte[] key;
    private final byte[] inputText;
    private final boolean doingDec;
    private final File outputFile;



    public CBCMachine(File inputFile, File keyFile, File ivFile, boolean doingDec, File outputFile) throws IOException {
        this.IV = new byte[16];
        this.key = new byte[16];
        int inputLength = (int) inputFile.length();
        inputLength = (inputLength % 16 == 0) ? inputLength : (inputLength / 16 + 1) * 16;
        this.inputText = new byte[inputLength]; // padding if needed
        this.doingDec = doingDec;
        this.outputFile = outputFile;

        // load data
        FileInputStream ivIS = new FileInputStream(ivFile);
        FileInputStream keyIS = new FileInputStream(keyFile);
        FileInputStream textIS = new FileInputStream(inputFile);
        ivIS.read(IV);
        keyIS.read(key);
        textIS.read(inputText);
        ivIS.close();
        keyIS.close();
        textIS.close();
    }

    public void start() throws IOException {
        if (!doingDec) {
            encrypt();
            System.out.println("Encing");
        } else {
            decrypt();
            System.out.println("Decing");
        }
    }

    private void encrypt() throws IOException {
        byte[] vector = new byte[16];
        byte[] curBlkProcessing = new byte[16];
        byte[] outputText = new byte[inputText.length];

        System.arraycopy(IV, 0, vector, 0, 16);
        System.arraycopy(inputText, 0, curBlkProcessing, 0, 16);

        AES aes;
        for (int blockID = 0; blockID * 16 < outputText.length; blockID++) {
            // XOR with IV
            for (int i = 0; i < 16; i++) {
                int tmp1 = curBlkProcessing[i] & 0b00000000000000000000000011111111;
                int tmp2 = vector[i] & 0b00000000000000000000000011111111;
                curBlkProcessing[i] = (byte) (tmp1 ^ tmp2);
            }

            aes = new AES(curBlkProcessing, key);
            aes.encrypt();
            // copy to output
            System.arraycopy(curBlkProcessing, 0, outputText, blockID * 16, 16);
            if ((blockID + 1) * 16 >= outputText.length) {
                break;
            }
            // getReady for the next Block
            System.arraycopy(curBlkProcessing, 0, vector, 0, 16);
            System.arraycopy(inputText, (blockID + 1) * 16, curBlkProcessing, 0, 16);
        }
        FileOutputStream fos = new FileOutputStream(outputFile);
        fos.write(outputText);
        fos.close();
    }

    private void decrypt() throws IOException {
        byte[] vector = new byte[16];
        byte[] curBlkProcessing = new byte[16];
        byte[] outputText = new byte[inputText.length];
        byte[] vCopy = new byte[16];

        System.arraycopy(IV, 0, vector, 0, 16);
        System.arraycopy(inputText, 0, curBlkProcessing, 0, 16);

        AES aes;
        for (int blockID = 0; blockID * 16 < outputText.length; blockID++) {
            System.arraycopy(curBlkProcessing, 0, vCopy, 0, 16);

            aes = new AES(curBlkProcessing, key);
            aes.decrypt();
            // XOR with IV
            for (int i = 0; i < 16; i++) {
                int tmp1 = curBlkProcessing[i] & 0b00000000000000000000000011111111;
                int tmp2 = vector[i] & 0b00000000000000000000000011111111;
                curBlkProcessing[i] = (byte) (tmp1 ^ tmp2);
            }
            // copy to output
            System.arraycopy(curBlkProcessing, 0, outputText, blockID * 16, 16);
            if ((blockID + 1) * 16 >= outputText.length) {
                break;
            }
            // getReady for the next Block
            System.arraycopy(vCopy, 0, vector, 0, 16);
            System.arraycopy(inputText, (blockID + 1) * 16, curBlkProcessing, 0, 16);
        }
        FileOutputStream fos = new FileOutputStream(outputFile);
        fos.write(outputText);
        fos.close();
    }

}
