package com.cloud.api.query.dao;

import com.cloud.api.query.vo.StoragePoolJoinVO;
import com.cloud.api.response.StoragePoolResponse;
import com.cloud.storage.StoragePool;
import com.cloud.utils.db.GenericDao;

import java.util.List;

public interface StoragePoolJoinDao extends GenericDao<StoragePoolJoinVO, Long> {

    StoragePoolResponse newStoragePoolResponse(StoragePoolJoinVO host);

    StoragePoolResponse setStoragePoolResponse(StoragePoolResponse response, StoragePoolJoinVO host);

    StoragePoolResponse newStoragePoolForMigrationResponse(StoragePoolJoinVO host);

    StoragePoolResponse setStoragePoolForMigrationResponse(StoragePoolResponse response, StoragePoolJoinVO host);

    List<StoragePoolJoinVO> newStoragePoolView(StoragePool group);

    List<StoragePoolJoinVO> searchByIds(Long... spIds);
}
