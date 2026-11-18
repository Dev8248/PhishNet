package com.phishnet.app.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import com.phishnet.app.models.QRPayload;
import com.phishnet.app.models.QRResult;

public class ScanHistoryDbHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "PhishNetHistory.db";
    private static final int DATABASE_VERSION = 1;

    private static final String TABLE_HISTORY = "scan_history";
    private static final String COLUMN_ID = "_id";
    private static final String COLUMN_TIMESTAMP = "timestamp";
    private static final String COLUMN_TYPE = "payload_type";
    private static final String COLUMN_RISK_SCORE = "risk_score";
    private static final String COLUMN_VERDICT = "verdict";
    private static final String COLUMN_CONTENT = "content_safe";

    public ScanHistoryDbHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        String createTable = "CREATE TABLE " + TABLE_HISTORY + " ("
                + COLUMN_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                + COLUMN_TIMESTAMP + " INTEGER, "
                + COLUMN_TYPE + " TEXT, "
                + COLUMN_RISK_SCORE + " INTEGER, "
                + COLUMN_VERDICT + " TEXT, "
                + COLUMN_CONTENT + " TEXT)";
        db.execSQL(createTable);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_HISTORY);
        onCreate(db);
    }

    public void insertScan(QRResult result) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COLUMN_TIMESTAMP, System.currentTimeMillis());
        values.put(COLUMN_TYPE, result.payload.type.name());
        values.put(COLUMN_RISK_SCORE, result.score);
        values.put(COLUMN_VERDICT, result.level.name());

        // Privacy protection: mask sensitive data
        String safeContent = result.payload.rawContent;
        if (result.payload.type == QRPayload.Type.WIFI_CONFIG) {
            safeContent = safeContent.replaceAll("P:[^;]+;", "P:********;");
        } else if (result.payload.type == QRPayload.Type.UPI_URI) {
            safeContent = safeContent.replaceAll("pa=[^&]+", "pa=********");
        } else if (result.payload.type == QRPayload.Type.VCARD) {
            safeContent = "Contact details hidden for privacy";
        } else if (result.payload.type == QRPayload.Type.EMAIL) {
            safeContent = "Email address hidden for privacy";
        } else if (result.payload.type == QRPayload.Type.TELEPHONE || result.payload.type == QRPayload.Type.SMS) {
            safeContent = "Phone number hidden for privacy";
        }
        values.put(COLUMN_CONTENT, safeContent);

        db.insert(TABLE_HISTORY, null, values);
        db.close();
    }

    public void clearHistory() {
        SQLiteDatabase db = this.getWritableDatabase();
        db.delete(TABLE_HISTORY, null, null);
        db.close();
    }
}
