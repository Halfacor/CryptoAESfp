package hongyzeng.aes;

/**
 * Handles one block of encryption/decryption
 */
public class AES {
    private final byte[] inputText;
    private final byte[][] expandedKeys;
    private static final byte[][] ISbox = new byte[][] {
            {(byte) 0x52, (byte) 0x09, (byte) 0x6A, (byte) 0xD5, (byte) 0x30, (byte) 0x36, (byte) 0xA5, (byte) 0x38, (byte) 0xBF, (byte) 0x40, (byte) 0xA3, (byte) 0x9E, (byte) 0x81, (byte) 0xF3, (byte) 0xD7, (byte) 0xFB},
            {(byte) 0x7C, (byte) 0xE3, (byte) 0x39, (byte) 0x82, (byte) 0x9B, (byte) 0x2F, (byte) 0xFF, (byte) 0x87, (byte) 0x34, (byte) 0x8E, (byte) 0x43, (byte) 0x44, (byte) 0xC4, (byte) 0xDE, (byte) 0xE9, (byte) 0xCB},
            {(byte) 0x54, (byte) 0x7B, (byte) 0x94, (byte) 0x32, (byte) 0xA6, (byte) 0xC2, (byte) 0x23, (byte) 0x3D, (byte) 0xEE, (byte) 0x4C, (byte) 0x95, (byte) 0x0B, (byte) 0x42, (byte) 0xFA, (byte) 0xC3, (byte) 0x4E},
            {(byte) 0x08, (byte) 0x2E, (byte) 0xA1, (byte) 0x66, (byte) 0x28, (byte) 0xD9, (byte) 0x24, (byte) 0xB2, (byte) 0x76, (byte) 0x5B, (byte) 0xA2, (byte) 0x49, (byte) 0x6D, (byte) 0x8B, (byte) 0xD1, (byte) 0x25},
            {(byte) 0x72, (byte) 0xF8, (byte) 0xF6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xD4, (byte) 0xA4, (byte) 0x5C, (byte) 0xCC, (byte) 0x5D, (byte) 0x65, (byte) 0xB6, (byte) 0x92},
            {(byte) 0x6C, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xFD, (byte) 0xED, (byte) 0xB9, (byte) 0xDA, (byte) 0x5E, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xA7, (byte) 0x8D, (byte) 0x9D, (byte) 0x84},
            {(byte) 0x90, (byte) 0xD8, (byte) 0xAB, (byte) 0x00, (byte) 0x8C, (byte) 0xBC, (byte) 0xD3, (byte) 0x0A, (byte) 0xF7, (byte) 0xE4, (byte) 0x58, (byte) 0x05, (byte) 0xB8, (byte) 0xB3, (byte) 0x45, (byte) 0x06},
            {(byte) 0xD0, (byte) 0x2C, (byte) 0x1E, (byte) 0x8F, (byte) 0xCA, (byte) 0x3F, (byte) 0x0F, (byte) 0x02, (byte) 0xC1, (byte) 0xAF, (byte) 0xBD, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8A, (byte) 0x6B},
            {(byte) 0x3A, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4F, (byte) 0x67, (byte) 0xDC, (byte) 0xEA, (byte) 0x97, (byte) 0xF2, (byte) 0xCF, (byte) 0xCE, (byte) 0xF0, (byte) 0xB4, (byte) 0xE6, (byte) 0x73},
            {(byte) 0x96, (byte) 0xAC, (byte) 0x74, (byte) 0x22, (byte) 0xE7, (byte) 0xAD, (byte) 0x35, (byte) 0x85, (byte) 0xE2, (byte) 0xF9, (byte) 0x37, (byte) 0xE8, (byte) 0x1C, (byte) 0x75, (byte) 0xDF, (byte) 0x6E},
            {(byte) 0x47, (byte) 0xF1, (byte) 0x1A, (byte) 0x71, (byte) 0x1D, (byte) 0x29, (byte) 0xC5, (byte) 0x89, (byte) 0x6F, (byte) 0xB7, (byte) 0x62, (byte) 0x0E, (byte) 0xAA, (byte) 0x18, (byte) 0xBE, (byte) 0x1B},
            {(byte) 0xFC, (byte) 0x56, (byte) 0x3E, (byte) 0x4B, (byte) 0xC6, (byte) 0xD2, (byte) 0x79, (byte) 0x20, (byte) 0x9A, (byte) 0xDB, (byte) 0xC0, (byte) 0xFE, (byte) 0x78, (byte) 0xCD, (byte) 0x5A, (byte) 0xF4},
            {(byte) 0x1F, (byte) 0xDD, (byte) 0xA8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xC7, (byte) 0x31, (byte) 0xB1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xEC, (byte) 0x5F},
            {(byte) 0x60, (byte) 0x51, (byte) 0x7F, (byte) 0xA9, (byte) 0x19, (byte) 0xB5, (byte) 0x4A, (byte) 0x0D, (byte) 0x2D, (byte) 0xE5, (byte) 0x7A, (byte) 0x9F, (byte) 0x93, (byte) 0xC9, (byte) 0x9C, (byte) 0xEF},
            {(byte) 0xA0, (byte) 0xE0, (byte) 0x3B, (byte) 0x4D, (byte) 0xAE, (byte) 0x2A, (byte) 0xF5, (byte) 0xB0, (byte) 0xC8, (byte) 0xEB, (byte) 0xBB, (byte) 0x3C, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61},
            {(byte) 0x17, (byte) 0x2B, (byte) 0x04, (byte) 0x7E, (byte) 0xBA, (byte) 0x77, (byte) 0xD6, (byte) 0x26, (byte) 0xE1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0C, (byte) 0x7D}
    };
//    private static final byte[][] fwMixColMat = new byte[][] {
//            {(byte) 0x02, (byte) 0x03, (byte) 0x01, (byte) 0x01},
//            {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x01},
//            {(byte) 0x01, (byte) 0x01, (byte) 0x02, (byte) 0x03},
//            {(byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x02}
//    };



    public AES(byte[] input, byte[] key) {
        inputText = input;
        KeyExpansion ke = new KeyExpansion(key);
        expandedKeys = ke.getExpandedKeys();
    }

    public void encrypt() {
        byte[][] state = new byte[4][4];
        // put inputText into the state
        for (int i = 0; i < 16; i++) {
            int r = i % 4;
            int c = i / 4;
            state[r][c] = inputText[i];
        }
        // round 0
        addRoundKey(state,0, false);
        // round 1 to 9
        for (int n = 1; n <= 9; n++) {
            subBytes(state, false);
            shiftRows(state, false);
            mixColumns(state, false);
            addRoundKey(state, n, false);
        }
        // round 10
        subBytes(state, false);
        shiftRows(state, false);
        addRoundKey(state, 10, false);

        // output cipherText, inplace
        for (int i = 0; i < 16; i++) {
            inputText[i] = state[i % 4][i / 4];
        }
    }


    public void decrypt() {
        byte[][] state = new byte[4][4];
        // put inputText into the state
        for (int i = 0; i < 16; i++) {
            int r = i % 4;
            int c = i / 4;
            state[r][c] = inputText[i];
        }

        // round 0
        addRoundKey(state, 0, true);
        // round 1 to 9
        for (int n = 1; n <= 9; n++) {
            shiftRows(state, true);
            subBytes(state, true);
            addRoundKey(state, n, true);
            mixColumns(state, true);
        }

        // round 10
        shiftRows(state, true);
        subBytes(state, true);
        addRoundKey(state, 10, true);

        // output cipherText, inplace
        for (int i = 0; i < 16; i++) {
            inputText[i] = state[i % 4][i / 4];
        }
    }


    private void addRoundKey(byte[][] state, int roundNum, boolean inverse) {
        if (!inverse) {
            for (int r = 0; r < 4; r++) {
                for (int c = 0; c < 4; c++) {
                    state[r][c] = Galos28.add(state[r][c], expandedKeys[r][c + roundNum * 4]);
                }
            }
        } else {
            for (int r = 0; r < 4; r++) {
                for (int c = 0; c < 4; c++) {
                    state[r][c] = Galos28.add(state[r][c], expandedKeys[r][40 - roundNum * 4 + c]);
                }
            }
        }
    }


    private void subBytes(byte[][] state, boolean inverse) {
        byte[][] sb = KeyExpansion.Sbox;
        if (inverse) {
            sb = ISbox;
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int x, y;
                byte copy = state[i][j];
                y = (copy & 0b00000000000000000000000000001111);
                x = (copy & 0b00000000000000000000000011110000) >> 4;
                state[i][j] = sb[x][y];
            }
        }
    }

    private void shiftRows(byte[][] state, boolean inverse) {
        for (int r = 1; r < 4; r++) {
            byte[] copy = new byte[4];
            System.arraycopy(state[r], 0, copy, 0, 4);
            int offset = inverse ? -r : r;
            for (int c = 0; c < 4; c++) {
                state[r][c] = copy[(c + offset + 4) % 4];
            }
        }
    }

    private void mixColumns(byte[][] state, boolean inverse) {
        byte[][] copy = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            System.arraycopy(state[i], 0, copy[i], 0, 4);
        }

        if (!inverse) {
            for (int r = 0; r < 4; r++) {
                for (int c = 0; c < 4; c++) {
                    switch (r) {
                        case 0 -> state[0][c] = Galos28.add(
                                Galos28.add(Galos28.multiply((byte) 2, copy[0][c]), Galos28.multiply((byte) 3, copy[1][c])),
                                Galos28.add(copy[2][c], copy[3][c])
                        );
                        case 1 -> state[1][c] = Galos28.add(
                                Galos28.add(copy[0][c], Galos28.multiply((byte) 2, copy[1][c])),
                                Galos28.add(Galos28.multiply((byte) 3, copy[2][c]), copy[3][c])
                        );
                        case 2 -> state[2][c] = Galos28.add(
                                Galos28.add(copy[0][c], copy[1][c]),
                                Galos28.add(Galos28.multiply((byte) 2, copy[2][c]), Galos28.multiply((byte) 3, copy[3][c]))
                        );
                        case 3 -> state[3][c] = Galos28.add(
                                Galos28.add(Galos28.multiply((byte) 3, copy[0][c]), copy[1][c]),
                                Galos28.add(copy[2][c], Galos28.multiply((byte) 2, copy[3][c]))
                        );
                        default -> {
                        }
                    }
                }
            }
        } else {
            for (int r = 0; r < 4; r++) {
                for (int c = 0; c < 4; c++) {
                    switch (r) {
                        case 0 -> state[0][c] = Galos28.add(
                                Galos28.add(Galos28.multiply((byte) 0x0E, copy[0][c]), Galos28.multiply((byte) 0x0B, copy[1][c])),
                                Galos28.add(Galos28.multiply((byte) 0x0D, copy[2][c]), Galos28.multiply((byte) 0x09, copy[3][c]))
                        );
                        case 1 -> state[1][c] = Galos28.add(
                                Galos28.add(Galos28.multiply((byte) 0x09, copy[0][c]), Galos28.multiply((byte) 0x0E, copy[1][c])),
                                Galos28.add(Galos28.multiply((byte) 0x0B, copy[2][c]), Galos28.multiply((byte) 0x0D, copy[3][c]))
                        );
                        case 2 -> state[2][c] = Galos28.add(
                                Galos28.add(Galos28.multiply((byte) 0x0D, copy[0][c]), Galos28.multiply((byte) 0x09, copy[1][c])),
                                Galos28.add(Galos28.multiply((byte) 0x0E, copy[2][c]), Galos28.multiply((byte) 0x0B, copy[3][c]))
                        );
                        case 3 -> state[3][c] = Galos28.add(
                                Galos28.add(Galos28.multiply((byte) 0x0B, copy[0][c]), Galos28.multiply((byte) 0x0D, copy[1][c])),
                                Galos28.add(Galos28.multiply((byte) 0x09, copy[2][c]), Galos28.multiply((byte) 0x0E, copy[3][c]))
                        );
                        default -> {
                        }
                    }
                }
            }
        }
    }


    private void keysPrintHelper() {
        for (int c = 0; c < 44; c++) {
            System.out.printf("w%d: %d %d %d %d \n", c, expandedKeys[0][c], expandedKeys[1][c], expandedKeys[2][c],expandedKeys[3][c]);
        }
    }

    private void textPrintHelper() {
        System.out.print("Text is: ");
        for (int c = 0; c < 16; c++) {
            System.out.print(Integer.toHexString((inputText[c] & 0b00000000000000000000000011111111)));
        }
        System.out.println("");
    }


    public static void main(String[] args) {
        byte[] plainText = new byte[] {(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
                                    (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
                                    (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98,
                                    (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10};

        byte[] key = new byte[] {(byte) 0x0f, (byte) 0x15, (byte) 0x71, (byte) 0xc9,
                                (byte) 0x47, (byte) 0xd9, (byte) 0xe8, (byte) 0x59,
                                (byte) 0x0c, (byte) 0xb7, (byte) 0xad, (byte) 0xd6,
                                (byte) 0xaf, (byte) 0x7f, (byte) 0x67, (byte) 0x98};

        byte[] cipherText = new byte[] {(byte) 0xff, (byte) 0x0b, (byte) 0x84, (byte) 0x4a,
                                        (byte) 0x08, (byte) 0x53, (byte) 0xbf, (byte) 0x7c,
                                        (byte) 0x69, (byte) 0x34, (byte) 0xab, (byte) 0x43,
                                        (byte) 0x64, (byte) 0x14, (byte) 0x8f, (byte) 0xb9};
//        AES aes = new AES(plainText, key);
//        aes.encrypt();
        AES aes = new AES(cipherText, key);
        aes.decrypt();
        aes.textPrintHelper();
    }
}
