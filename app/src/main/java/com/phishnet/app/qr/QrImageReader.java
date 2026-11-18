package com.phishnet.app.qr;

import android.content.ContentResolver;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;

import java.io.IOException;
import java.io.InputStream;

/**
 * Loads an image the user picked through the system photo picker and decodes a QR code from it.
 * Works only on the one image the user selected: no storage permission is requested. The image is
 * down-sampled so large photos cannot exhaust memory, and is never uploaded or kept.
 */
public final class QrImageReader {
    private static final int[] MAX_SIDES = {2048, 1024};

    /** @return the QR payload text, or null if the image is unreadable or has no QR code. */
    public static String read(ContentResolver resolver, Uri uri) {
        try {
            String type = resolver.getType(uri);
            if (type != null && !type.startsWith("image/")) {
                return null;
            }
            BitmapFactory.Options bounds = new BitmapFactory.Options();
            bounds.inJustDecodeBounds = true;
            try (InputStream in = resolver.openInputStream(uri)) {
                if (in == null) return null;
                BitmapFactory.decodeStream(in, null, bounds);
            }
            if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
                return null;
            }
            int lastSample = -1;
            for (int maxSide : MAX_SIDES) {
                int sample = 1;
                while (Math.max(bounds.outWidth, bounds.outHeight) / sample > maxSide) {
                    sample *= 2;
                }
                if (sample == lastSample) continue;
                lastSample = sample;

                BitmapFactory.Options opts = new BitmapFactory.Options();
                opts.inSampleSize = sample;
                opts.inPreferredConfig = Bitmap.Config.ARGB_8888;
                Bitmap bitmap;
                try (InputStream in = resolver.openInputStream(uri)) {
                    if (in == null) return null;
                    bitmap = BitmapFactory.decodeStream(in, null, opts);
                }
                if (bitmap == null) continue;
                try {
                    int w = bitmap.getWidth();
                    int h = bitmap.getHeight();
                    int[] pixels = new int[w * h];
                    bitmap.getPixels(pixels, 0, w, 0, 0, w, h);
                    String text = QrDecoder.decode(pixels, w, h);
                    if (text != null) return text;
                } finally {
                    bitmap.recycle();
                }
            }
            return null;
        } catch (IOException | RuntimeException | OutOfMemoryError e) { // includes SecurityException
            return null;
        }
    }

    private QrImageReader() {}
}
