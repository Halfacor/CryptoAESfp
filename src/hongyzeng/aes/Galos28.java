package hongyzeng.aes;

class Galos28 {
    // https://stackoverflow.com/questions/24004579/xor-bytes-in-java
    // https://stackoverflow.com/questions/7401550/how-to-convert-int-to-unsigned-byte-and-back

    static byte add(byte a, byte b) {
        int tmp1 = a & 0b00000000000000000000000011111111;
        int tmp2 = b & 0b00000000000000000000000011111111;
        return (byte) (tmp1 ^ tmp2);
    }

    static byte multiply(byte a, byte b) {
        //System.out.println("b is " + Integer.toBinaryString(b & 0b00000000000000000000000011111111));
        // similar to fast exp
        if (a == 0 || b == 0) {
            return (byte) 0;
        }
        byte p = a;
        byte ans = 0b0;
        //System.out.println("p is " + Integer.toBinaryString(p & 0b00000000000000000000000011111111));
        while (b != 0) {
            if ((b & 1) != 0) { // b0 is 1
                ans = add(ans, p);
            }
            p = mul2(p);
            //System.out.println("updated p is " + Integer.toBinaryString(p & 0b00000000000000000000000011111111));
            int tmp = b & 0b00000000000000000000000011111111;
            tmp >>= 1;
            b = (byte) tmp;
        }
        return ans;
    }


    static byte mul2(byte b) {
        if ( ((b >> 7) & 1) == 1) { // b7 is 1
            int tmp = b & 0b00000000000000000000000011111111;
            tmp <<= 1;
            b = (byte) tmp;
            //System.out.println("in mul2, b is " + Integer.toBinaryString(b & 0b00000000000000000000000011111111));
            return add(b, (byte) 0b00011011);

        } else { // b7 is 0
            int tmp = b & 0b00000000000000000000000011111111;
            tmp <<= 1;
            b = (byte) tmp;
            return b;
        }
    }

    public static void main(String[] args) {
        //byte ans = (multiply((byte) 0b01010111, (byte) 0b10000011));
        //byte ans = mul2((byte) 0b01010111);
        //System.out.println(Integer.toBinaryString(ans & 0b00000000000000000000000011111111));
        //byte[] arr = new byte[]{1};
    }
}
