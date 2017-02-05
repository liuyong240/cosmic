package com.cloud.network;

import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.cloud.network.dao.IPAddressDao;
import com.cloud.network.dao.IPAddressVO;
import com.cloud.network.rules.StaticNat;
import com.cloud.network.rules.StaticNatImpl;
import com.cloud.utils.net.Ip;

import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class IpAddressManagerTest {

    @Mock
    IPAddressDao _ipAddressDao;

    @InjectMocks
    IpAddressManagerImpl _ipManager;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetStaticNatSourceIps() {
        final String publicIpAddress = "192.168.1.3";
        final IPAddressVO vo = mock(IPAddressVO.class);
        when(vo.getAddress()).thenReturn(new Ip(publicIpAddress));
        when(vo.getId()).thenReturn(1l);

        when(_ipAddressDao.findById(anyLong())).thenReturn(vo);
        final StaticNat snat = new StaticNatImpl(1, 1, 1, 1, publicIpAddress, false);

        final List<IPAddressVO> ips = _ipManager.getStaticNatSourceIps(Collections.singletonList(snat));
        Assert.assertNotNull(ips);
        Assert.assertEquals(1, ips.size());

        final IPAddressVO returnedVO = ips.get(0);
        Assert.assertEquals(vo, returnedVO);
    }
}