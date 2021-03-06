package com.cloud.storage.snapshot;

import com.cloud.engine.subsystem.api.storage.SnapshotInfo;
import com.cloud.engine.subsystem.api.storage.SnapshotService;
import com.cloud.engine.subsystem.api.storage.SnapshotStrategy;

import javax.inject.Inject;

public abstract class SnapshotStrategyBase implements SnapshotStrategy {
    @Inject
    SnapshotService snapshotSvr;

    @Override
    public SnapshotInfo takeSnapshot(final SnapshotInfo snapshot) {
        return snapshotSvr.takeSnapshot(snapshot).getSnashot();
    }

    @Override
    public SnapshotInfo backupSnapshot(final SnapshotInfo snapshot) {
        return snapshotSvr.backupSnapshot(snapshot);
    }

    @Override
    public boolean revertSnapshot(final SnapshotInfo snapshot) {
        return snapshotSvr.revertSnapshot(snapshot);
    }
}
