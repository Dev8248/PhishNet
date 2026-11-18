package com.phishnet.app.analysis;

public interface ScanProgressListener {
    void onStageStatusChanged(int stageId, int status); // 0=PENDING, 1=RUNNING, 2=SUCCESS, 3=WARNING, 4=FAILURE
}
