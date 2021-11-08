package hongyzeng.aes;

/**
 * Handles one block of encryption/decryption
 */
public class AES {
    private final byte[] inputText;
    private final byte[][] expandedKeys;

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
        addRoundKey(state,0);
        // round 1 to 9
        for (int n = 1; n <= 9; n++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, n);
        }
        // round 10
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, 10);

        // output cipherText, inplace
        for (int i = 0; i < 16; i++) {
            inputText[i] = state[i % 4][i / 4];
        }
    }


    private void addRoundKey(byte[][] state, int roundNum) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = Galos28.add(state[r][c], expandedKeys[r][c + roundNum * 4]);
            }
        }
    }


    private void subBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int x, y;
                byte copy = state[i][j];
                y = (copy & 0b00000000000000000000000000001111);
                x = (copy & 0b00000000000000000000000011110000) >> 4;
                state[i][j] = KeyExpansion.Sbox[x][y];
            }
        }
    }

    private void shiftRows(byte[][] state) {
        for (int r = 1; r < 4; r++) {
            byte[] copy = new byte[4];
            for (int c = 0; c < 4; c++) {
                copy[c] = state[r][c];
            }

            for (int c = 0; c < 4; c++) {
                state[r][c] = copy[(c + r) % 4];
            }
        }
    }

    private void mixColumns(byte[][] state) {
        byte[][] copy = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                copy[i][j] = state[i][j];
            }
        }


        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                switch (r) {
                    case 0:
                        state[0][c] = Galos28.add(
                                Galos28.add( Galos28.multiply( (byte) 2, copy[0][c] ), Galos28.multiply( (byte) 3, copy[1][c] )),
                                Galos28.add( copy[2][c], copy[3][c] )
                        );
                        break;
                    case 1:
                        state[1][c] = Galos28.add(
                                Galos28.add(  copy[0][c] , Galos28.multiply( (byte) 2, copy[1][c] )),
                                Galos28.add( Galos28.multiply( (byte) 3, copy[2][c] ), copy[3][c] )
                        );
                        break;
                    case 2:
                        state[2][c] = Galos28.add(
                                Galos28.add(  copy[0][c] , copy[1][c] ),
                                Galos28.add( Galos28.multiply( (byte) 2, copy[2][c] ), Galos28.multiply( (byte) 3, copy[3][c] ) )
                        );
                        break;
                    case 3:
                        state[3][c] = Galos28.add(
                                Galos28.add( Galos28.multiply( (byte) 3, copy[0][c] ) , copy[1][c] ),
                                Galos28.add( copy[2][c], Galos28.multiply( (byte) 2, copy[3][c] ) )
                        );
                        break;
                    default:
                        break;
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
        AES aes = new AES(plainText, key);
        aes.encrypt();
        aes.textPrintHelper();
    }
}
