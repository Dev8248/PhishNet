package com.phishnet.app.qr;

import static org.junit.Assert.*;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import java.util.Random;
import org.junit.Test;

public class QrDecoderTest {
    private static final int BLACK = 0xFF000000;
    private static final int WHITE = 0xFFFFFFFF;

    private static int[] render(String text, int size, boolean invert) throws WriterException {
        BitMatrix m = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size);
        int[] px = new int[size * size];
        for (int y = 0; y < size; y++) {
            for (int x = 0; x < size; x++) {
                boolean dark = m.get(x, y);
                px[y * size + x] = (dark ^ invert) ? BLACK : WHITE;
            }
        }
        return px;
    }

    @Test public void decodesAGeneratedCode() throws Exception {
        String url = "https://example.com/hello?a=1";
        assertEquals(url, QrDecoder.decode(render(url, 300, false), 300, 300));
    }

    @Test public void decodesLightOnDarkCodes() throws Exception {
        String url = "https://example.org/inverted";
        assertEquals(url, QrDecoder.decode(render(url, 300, true), 300, 300));
    }

    @Test public void decodesNonLinkPayloadsToo() throws Exception {
        String text = "WIFI:S:home;T:WPA;P:secret;;";
        assertEquals(text, QrDecoder.decode(render(text, 300, false), 300, 300));
    }

    @Test public void blankAndNoisyImagesGiveNull() {
        int[] white = new int[200 * 200];
        java.util.Arrays.fill(white, WHITE);
        assertNull(QrDecoder.decode(white, 200, 200));
        int[] noise = new int[200 * 200];
        Random r = new Random(7);
        for (int i = 0; i < noise.length; i++) noise[i] = r.nextBoolean() ? BLACK : WHITE;
        assertNull(QrDecoder.decode(noise, 200, 200));
    }

    @Test public void invalidArgumentsGiveNullInsteadOfCrashing() {
        assertNull(QrDecoder.decode(null, 10, 10));
        assertNull(QrDecoder.decode(new int[5], 10, 10));
        assertNull(QrDecoder.decode(new int[100], 0, 10));
        assertNull(QrDecoder.decode(new int[100], 10, -1));
    }
}
