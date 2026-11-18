package com.phishnet.app.qr;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.Binarizer;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.ChecksumException;
import com.google.zxing.DecodeHintType;
import com.google.zxing.FormatException;
import com.google.zxing.LuminanceSource;
import com.google.zxing.NotFoundException;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.GlobalHistogramBinarizer;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.multi.qrcode.QRCodeMultiReader;
import com.google.zxing.qrcode.QRCodeReader;
import com.phishnet.app.analysis.Limits;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

/**
 * Decodes QR codes from raw pixels, entirely on the device, using the ZXing core library.
 * Pure Java (no Android classes) so it can be unit tested on a plain JVM.
 */
public final class QrDecoder {

    /**
     * @param argb ARGB pixels, row by row
     * @return the decoded text (several codes are joined by new lines), or null if no QR code was found
     */
    public static String decode(int[] argb, int width, int height) {
        if (argb == null || width <= 0 || height <= 0 || (long) width * height > argb.length) {
            return null;
        }
        try {
            LuminanceSource source = new RGBLuminanceSource(width, height, argb);
            return tryAllSafely(source);
        } catch (RuntimeException e) {
            return null;
        }
    }

    public static String decodeYuv(byte[] yuv, int dataWidth, int dataHeight, int cropWidth, int cropHeight) {
        if (yuv == null || dataWidth <= 0 || dataHeight <= 0 || (long) dataWidth * dataHeight > yuv.length) {
            return null;
        }
        try {
            LuminanceSource source = new com.google.zxing.PlanarYUVLuminanceSource(
                    yuv, dataWidth, dataHeight, 0, 0, cropWidth, cropHeight, false);
            return tryAllSafely(source);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String tryAllSafely(LuminanceSource source) {
        String text = tryAll(source);
        if (text == null) {
            text = tryAll(source.invert()); // light-on-dark codes
        }
        if (text != null && text.length() > Limits.MAX_INPUT_CHARS) {
            text = text.substring(0, Limits.MAX_INPUT_CHARS);
        }
        return text;
    }

    private static String tryAll(LuminanceSource source) {
        Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
        hints.put(DecodeHintType.POSSIBLE_FORMATS, Collections.singletonList(BarcodeFormat.QR_CODE));
        hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        for (int pass = 0; pass < 2; pass++) {
            Binarizer binarizer = pass == 0 ? new HybridBinarizer(source) : new GlobalHistogramBinarizer(source);
            BinaryBitmap bitmap = new BinaryBitmap(binarizer);
            try {
                Result[] results = new QRCodeMultiReader().decodeMultiple(bitmap, hints);
                StringBuilder b = new StringBuilder();
                for (Result r : results) {
                    if (b.length() > 0) b.append('\n');
                    b.append(r.getText());
                }
                if (b.length() > 0) return b.toString();
            } catch (NotFoundException e) {
                // fall through to the single-code reader
            }
            try {
                return new QRCodeReader().decode(bitmap, hints).getText();
            } catch (NotFoundException | ChecksumException | FormatException e) {
                // try the next binarizer
            }
        }
        return null;
    }

    private QrDecoder() {}
}
