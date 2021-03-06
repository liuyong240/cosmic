package com.cloud.resource;

import com.cloud.agent.AgentManager;
import com.cloud.agent.api.Answer;
import com.cloud.agent.api.Command;
import com.cloud.agent.api.GetGPUStatsAnswer;
import com.cloud.agent.api.GetGPUStatsCommand;
import com.cloud.agent.api.GetHostStatsAnswer;
import com.cloud.agent.api.GetHostStatsCommand;
import com.cloud.agent.api.MaintainAnswer;
import com.cloud.agent.api.MaintainCommand;
import com.cloud.agent.api.PropagateResourceEventCommand;
import com.cloud.agent.api.StartupCommand;
import com.cloud.agent.api.StartupRoutingCommand;
import com.cloud.agent.api.UnsupportedAnswer;
import com.cloud.agent.api.UpdateHostPasswordCommand;
import com.cloud.agent.api.VgpuTypesInfo;
import com.cloud.agent.api.to.GPUDeviceTO;
import com.cloud.agent.transport.Request;
import com.cloud.api.ApiConstants;
import com.cloud.api.command.admin.cluster.AddClusterCmd;
import com.cloud.api.command.admin.cluster.DeleteClusterCmd;
import com.cloud.api.command.admin.host.AddHostCmd;
import com.cloud.api.command.admin.host.AddSecondaryStorageCmd;
import com.cloud.api.command.admin.host.CancelMaintenanceCmd;
import com.cloud.api.command.admin.host.PrepareForMaintenanceCmd;
import com.cloud.api.command.admin.host.ReconnectHostCmd;
import com.cloud.api.command.admin.host.UpdateHostCmd;
import com.cloud.api.command.admin.host.UpdateHostPasswordCmd;
import com.cloud.capacity.Capacity;
import com.cloud.capacity.CapacityManager;
import com.cloud.capacity.CapacityState;
import com.cloud.capacity.CapacityVO;
import com.cloud.capacity.dao.CapacityDao;
import com.cloud.cluster.ClusterManager;
import com.cloud.configuration.Config;
import com.cloud.configuration.ConfigurationManager;
import com.cloud.context.CallContext;
import com.cloud.dc.ClusterDetailsDao;
import com.cloud.dc.ClusterDetailsVO;
import com.cloud.dc.ClusterVO;
import com.cloud.dc.DataCenter.NetworkType;
import com.cloud.dc.DataCenterIpAddressVO;
import com.cloud.dc.DataCenterVO;
import com.cloud.dc.DedicatedResourceVO;
import com.cloud.dc.HostPodVO;
import com.cloud.dc.PodCluster;
import com.cloud.dc.dao.ClusterDao;
import com.cloud.dc.dao.DataCenterDao;
import com.cloud.dc.dao.DataCenterIpAddressDao;
import com.cloud.dc.dao.DedicatedResourceDao;
import com.cloud.dc.dao.HostPodDao;
import com.cloud.deploy.PlannerHostReservationVO;
import com.cloud.deploy.dao.PlannerHostReservationDao;
import com.cloud.event.ActionEvent;
import com.cloud.event.ActionEventUtils;
import com.cloud.event.EventTypes;
import com.cloud.event.EventVO;
import com.cloud.exception.AgentUnavailableException;
import com.cloud.exception.DiscoveryException;
import com.cloud.exception.ResourceInUseException;
import com.cloud.framework.config.dao.ConfigurationDao;
import com.cloud.gpu.GPU;
import com.cloud.gpu.HostGpuGroupsVO;
import com.cloud.gpu.VGPUTypesVO;
import com.cloud.gpu.dao.HostGpuGroupsDao;
import com.cloud.gpu.dao.VGPUTypesDao;
import com.cloud.ha.HighAvailabilityManager;
import com.cloud.ha.HighAvailabilityManager.WorkType;
import com.cloud.host.DetailVO;
import com.cloud.host.Host;
import com.cloud.host.Host.Type;
import com.cloud.host.HostStats;
import com.cloud.host.HostVO;
import com.cloud.host.Status;
import com.cloud.host.Status.Event;
import com.cloud.host.dao.HostDao;
import com.cloud.host.dao.HostDetailsDao;
import com.cloud.host.dao.HostTagsDao;
import com.cloud.hypervisor.Hypervisor;
import com.cloud.hypervisor.Hypervisor.HypervisorType;
import com.cloud.hypervisor.kvm.discoverer.KvmDummyResourceBase;
import com.cloud.network.dao.IPAddressDao;
import com.cloud.network.dao.IPAddressVO;
import com.cloud.org.Cluster;
import com.cloud.org.Grouping;
import com.cloud.org.Managed;
import com.cloud.serializer.GsonHelper;
import com.cloud.service.dao.ServiceOfferingDetailsDao;
import com.cloud.storage.GuestOSCategoryVO;
import com.cloud.storage.StorageManager;
import com.cloud.storage.StoragePool;
import com.cloud.storage.StoragePoolHostVO;
import com.cloud.storage.StoragePoolStatus;
import com.cloud.storage.StorageService;
import com.cloud.storage.VMTemplateVO;
import com.cloud.storage.dao.GuestOSCategoryDao;
import com.cloud.storage.dao.StoragePoolHostDao;
import com.cloud.storage.dao.VMTemplateDao;
import com.cloud.storage.datastore.db.PrimaryDataStoreDao;
import com.cloud.storage.datastore.db.StoragePoolVO;
import com.cloud.user.Account;
import com.cloud.user.AccountManager;
import com.cloud.utils.StringUtils;
import com.cloud.utils.UriUtils;
import com.cloud.utils.component.Manager;
import com.cloud.utils.component.ManagerBase;
import com.cloud.utils.db.DB;
import com.cloud.utils.db.Filter;
import com.cloud.utils.db.GenericSearchBuilder;
import com.cloud.utils.db.GlobalLock;
import com.cloud.utils.db.JoinBuilder;
import com.cloud.utils.db.QueryBuilder;
import com.cloud.utils.db.SearchBuilder;
import com.cloud.utils.db.SearchCriteria;
import com.cloud.utils.db.SearchCriteria.Func;
import com.cloud.utils.db.SearchCriteria.Op;
import com.cloud.utils.db.Transaction;
import com.cloud.utils.db.TransactionCallback;
import com.cloud.utils.db.TransactionCallbackNoReturn;
import com.cloud.utils.db.TransactionLegacy;
import com.cloud.utils.db.TransactionStatus;
import com.cloud.utils.exception.CloudRuntimeException;
import com.cloud.utils.exception.InvalidParameterValueException;
import com.cloud.utils.fsm.NoTransitionException;
import com.cloud.utils.identity.ManagementServerNode;
import com.cloud.utils.net.Ip;
import com.cloud.utils.net.NetUtils;
import com.cloud.utils.ssh.SSHCmdHelper;
import com.cloud.utils.ssh.SshException;
import com.cloud.vm.VMInstanceVO;
import com.cloud.vm.VirtualMachine.State;
import com.cloud.vm.VirtualMachineManager;
import com.cloud.vm.dao.VMInstanceDao;

import javax.inject.Inject;
import javax.naming.ConfigurationException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import org.apache.commons.lang.ObjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class ResourceManagerImpl extends ManagerBase implements ResourceManager, ResourceService, Manager {
    private static final Logger s_logger = LoggerFactory.getLogger(ResourceManagerImpl.class);
    private static final int ACQUIRE_GLOBAL_LOCK_TIMEOUT_FOR_COOPERATION = 30; // seconds
    private final long _nodeId = ManagementServerNode.getManagementServerId();
    private final HashMap<String, ResourceStateAdapter> _resourceStateAdapters = new HashMap<>();
    private final HashMap<Integer, List<ResourceListener>> _lifeCycleListeners = new HashMap<>();
    @Inject
    protected HostGpuGroupsDao _hostGpuGroupsDao;
    @Inject
    protected VGPUTypesDao _vgpuTypesDao;
    Gson _gson;
    @Inject
    PlannerHostReservationDao _plannerHostReserveDao;
    @Inject
    private AccountManager _accountMgr;
    @Inject
    private AgentManager _agentMgr;
    @Inject
    private StorageManager _storageMgr;
    @Inject
    private DataCenterDao _dcDao;
    @Inject
    private HostPodDao _podDao;
    @Inject
    private ClusterDetailsDao _clusterDetailsDao;
    @Inject
    private ClusterDao _clusterDao;
    @Inject
    private CapacityDao _capacityDao;
    @Inject
    private HostDao _hostDao;
    @Inject
    private HostDetailsDao _hostDetailsDao;
    @Inject
    private ConfigurationDao _configDao;
    @Inject
    private HostTagsDao _hostTagsDao;
    @Inject
    private GuestOSCategoryDao _guestOSCategoryDao;
    @Inject
    private PrimaryDataStoreDao _storagePoolDao;
    @Inject
    private DataCenterIpAddressDao _privateIPAddressDao;
    @Inject
    private IPAddressDao _publicIPAddressDao;
    @Inject
    private VirtualMachineManager _vmMgr;
    @Inject
    private VMInstanceDao _vmDao;
    @Inject
    private HighAvailabilityManager _haMgr;
    @Inject
    private StorageService _storageSvr;
    @Inject
    private DedicatedResourceDao _dedicatedDao;
    @Inject
    private ServiceOfferingDetailsDao _serviceOfferingDetailsDao;
    private List<? extends Discoverer> _discoverers;
    @Inject
    private ClusterManager _clusterMgr;
    @Inject
    private StoragePoolHostDao _storagePoolHostDao;
    @Inject
    private VMTemplateDao _templateDao;
    @Inject
    private ConfigurationManager _configMgr;
    private HypervisorType _defaultSystemVMHypervisor;
    private GenericSearchBuilder<HostVO, String> _hypervisorsInDC;
    private SearchBuilder<HostGpuGroupsVO> _gpuAvailability;

    public List<? extends Discoverer> getDiscoverers() {
        return _discoverers;
    }

    public void setDiscoverers(final List<? extends Discoverer> discoverers) {
        _discoverers = discoverers;
    }

    @Override
    public void registerResourceEvent(final Integer event, final ResourceListener listener) {
        synchronized (_lifeCycleListeners) {
            if ((event & ResourceListener.EVENT_DISCOVER_BEFORE) != 0) {
                insertListener(ResourceListener.EVENT_DISCOVER_BEFORE, listener);
            }
            if ((event & ResourceListener.EVENT_DISCOVER_AFTER) != 0) {
                insertListener(ResourceListener.EVENT_DISCOVER_AFTER, listener);
            }
            if ((event & ResourceListener.EVENT_DELETE_HOST_BEFORE) != 0) {
                insertListener(ResourceListener.EVENT_DELETE_HOST_BEFORE, listener);
            }
            if ((event & ResourceListener.EVENT_DELETE_HOST_AFTER) != 0) {
                insertListener(ResourceListener.EVENT_DELETE_HOST_AFTER, listener);
            }
            if ((event & ResourceListener.EVENT_CANCEL_MAINTENANCE_BEFORE) != 0) {
                insertListener(ResourceListener.EVENT_CANCEL_MAINTENANCE_BEFORE, listener);
            }
            if ((event & ResourceListener.EVENT_CANCEL_MAINTENANCE_AFTER) != 0) {
                insertListener(ResourceListener.EVENT_CANCEL_MAINTENANCE_AFTER, listener);
            }
            if ((event & ResourceListener.EVENT_PREPARE_MAINTENANCE_BEFORE) != 0) {
                insertListener(ResourceListener.EVENT_PREPARE_MAINTENANCE_BEFORE, listener);
            }
            if ((event & ResourceListener.EVENT_PREPARE_MAINTENANCE_AFTER) != 0) {
                insertListener(ResourceListener.EVENT_PREPARE_MAINTENANCE_AFTER, listener);
            }
        }
    }

    private void insertListener(final Integer event, final ResourceListener listener) {
        List<ResourceListener> lst = _lifeCycleListeners.get(event);
        if (lst == null) {
            lst = new ArrayList<>();
            _lifeCycleListeners.put(event, lst);
        }

        if (lst.contains(listener)) {
            throw new CloudRuntimeException("Duplicate resource lisener:" + listener.getClass().getSimpleName());
        }

        lst.add(listener);
    }

    @Override
    public void unregisterResourceEvent(final ResourceListener listener) {
        synchronized (_lifeCycleListeners) {
            final Iterator it = _lifeCycleListeners.entrySet().iterator();
            while (it.hasNext()) {
                final Map.Entry<Integer, List<ResourceListener>> items = (Map.Entry<Integer, List<ResourceListener>>) it.next();
                final List<ResourceListener> lst = items.getValue();
                lst.remove(listener);
            }
        }
    }

    @Override
    public void registerResourceStateAdapter(final String name, final ResourceStateAdapter adapter) {
        synchronized (_resourceStateAdapters) {
            if (_resourceStateAdapters.get(name) != null) {
                throw new CloudRuntimeException(name + " has registered");
            }
            _resourceStateAdapters.put(name, adapter);
        }
    }

    @Override
    public void unregisterResourceStateAdapter(final String name) {
        synchronized (_resourceStateAdapters) {
            _resourceStateAdapters.remove(name);
        }
    }

    @Override
    public Host createHostAndAgent(final Long hostId, final ServerResource resource, final Map<String, String> details, final boolean old, final List<String> hostTags, final
    boolean forRebalance) {
        final Host host = createHostAndAgent(resource, details, old, hostTags, forRebalance);
        return host;
    }

    @Override
    public Host addHost(final long zoneId, final ServerResource resource, final Type hostType, final Map<String, String> hostDetails) {
        // Check if the zone exists in the system
        if (_dcDao.findById(zoneId) == null) {
            throw new InvalidParameterValueException("Can't find zone with id " + zoneId);
        }

        final Map<String, String> details = hostDetails;
        final String guid = details.get("guid");
        final List<HostVO> currentHosts = listAllUpAndEnabledHostsInOneZoneByType(hostType, zoneId);
        for (final HostVO currentHost : currentHosts) {
            if (currentHost.getGuid().equals(guid)) {
                return currentHost;
            }
        }

        return createHostAndAgent(resource, hostDetails, true, null, false);
    }

    @Override
    public HostVO createHostVOForConnectedAgent(final StartupCommand[] cmds) {
        return createHostVO(cmds, null, null, null, ResourceStateAdapter.Event.CREATE_HOST_VO_FOR_CONNECTED);
    }

    @Override
    public void checkCIDR(final HostPodVO pod, final DataCenterVO dc, final String serverPrivateIP, final String serverPrivateNetmask) throws IllegalArgumentException {
        if (serverPrivateIP == null) {
            return;
        }
        // Get the CIDR address and CIDR size
        final String cidrAddress = pod.getCidrAddress();
        final long cidrSize = pod.getCidrSize();

        // If the server's private IP address is not in the same subnet as the
        // pod's CIDR, return false
        final String cidrSubnet = NetUtils.getCidrSubNet(cidrAddress, cidrSize);
        final String serverSubnet = NetUtils.getSubNet(serverPrivateIP, serverPrivateNetmask);
        if (!cidrSubnet.equals(serverSubnet)) {
            s_logger.warn("The private ip address of the server (" + serverPrivateIP + ") is not compatible with the CIDR of pod: " + pod.getName() + " and zone: " +
                    dc.getName());
            throw new IllegalArgumentException("The private ip address of the server (" + serverPrivateIP + ") is not compatible with the CIDR of pod: " + pod.getName() +
                    " and zone: " + dc.getName());
        }

        // If the server's private netmask is less inclusive than the pod's CIDR
        // netmask, return false
        final String cidrNetmask = NetUtils.getCidrSubNet("255.255.255.255", cidrSize);
        final long cidrNetmaskNumeric = NetUtils.ip2Long(cidrNetmask);
        final long serverNetmaskNumeric = NetUtils.ip2Long(serverPrivateNetmask);
        if (serverNetmaskNumeric > cidrNetmaskNumeric) {
            throw new IllegalArgumentException("The private ip address of the server (" + serverPrivateIP + ") is not compatible with the CIDR of pod: " + pod.getName() +
                    " and zone: " + dc.getName());
        }
    }

    @Override
    public HostVO fillRoutingHostVO(final HostVO host, final StartupRoutingCommand ssCmd, final HypervisorType hyType, Map<String, String> details, final List<String> hostTags) {
        if (host.getPodId() == null) {
            s_logger.error("Host " + ssCmd.getPrivateIpAddress() + " sent incorrect pod, pod id is null");
            throw new IllegalArgumentException("Host " + ssCmd.getPrivateIpAddress() + " sent incorrect pod, pod id is null");
        }

        final ClusterVO clusterVO = _clusterDao.findById(host.getClusterId());
        if (clusterVO.getHypervisorType() != hyType) {
            throw new IllegalArgumentException("Can't add host whose hypervisor type is: " + hyType + " into cluster: " + clusterVO.getId() +
                    " whose hypervisor type is: " + clusterVO.getHypervisorType());
        }

        final Map<String, String> hostDetails = ssCmd.getHostDetails();
        if (hostDetails != null) {
            if (details != null) {
                details.putAll(hostDetails);
            } else {
                details = hostDetails;
            }
        }

        final HostPodVO pod = _podDao.findById(host.getPodId());
        final DataCenterVO dc = _dcDao.findById(host.getDataCenterId());
        checkIPConflicts(pod, dc, ssCmd.getPrivateIpAddress(), ssCmd.getPublicIpAddress(), ssCmd.getPublicIpAddress(), ssCmd.getPublicNetmask());
        host.setType(com.cloud.host.Host.Type.Routing);
        host.setDetails(details);
        host.setCaps(ssCmd.getCapabilities());
        host.setCpuSockets(ssCmd.getCpuSockets());
        host.setCpus(ssCmd.getCpus());
        host.setTotalMemory(ssCmd.getMemory());
        host.setSpeed(ssCmd.getSpeed());
        host.setHypervisorType(hyType);
        host.setHypervisorVersion(ssCmd.getHypervisorVersion());
        host.setGpuGroups(ssCmd.getGpuGroupDetails());
        return host;
    }

    private void checkIPConflicts(final HostPodVO pod, final DataCenterVO dc, final String serverPrivateIP, final String serverPrivateNetmask, final String serverPublicIP, final
    String serverPublicNetmask) {
        // If the server's private IP is the same as is public IP, this host has
        // a host-only private network. Don't check for conflicts with the
        // private IP address table.
        if (!ObjectUtils.equals(serverPrivateIP, serverPublicIP)) {
            if (!_privateIPAddressDao.mark(dc.getId(), pod.getId(), serverPrivateIP)) {
                // If the server's private IP address is already in the
                // database, return false
                final List<DataCenterIpAddressVO> existingPrivateIPs = _privateIPAddressDao.listByPodIdDcIdIpAddress(pod.getId(), dc.getId(), serverPrivateIP);

                assert existingPrivateIPs.size() <= 1 : " How can we get more than one ip address with " + serverPrivateIP;
                if (existingPrivateIPs.size() > 1) {
                    throw new IllegalArgumentException("The private ip address of the server (" + serverPrivateIP + ") is already in use in pod: " + pod.getName() +
                            " and zone: " + dc.getName());
                }
                if (existingPrivateIPs.size() == 1) {
                    final DataCenterIpAddressVO vo = existingPrivateIPs.get(0);
                    if (vo.getInstanceId() != null) {
                        throw new IllegalArgumentException("The private ip address of the server (" + serverPrivateIP + ") is already in use in pod: " + pod.getName() +
                                " and zone: " + dc.getName());
                    }
                }
            }
        }

        if (serverPublicIP != null && !_publicIPAddressDao.mark(dc.getId(), new Ip(serverPublicIP))) {
            // If the server's public IP address is already in the database,
            // return false
            final List<IPAddressVO> existingPublicIPs = _publicIPAddressDao.listByDcIdIpAddress(dc.getId(), serverPublicIP);
            if (existingPublicIPs.size() > 0) {
                throw new IllegalArgumentException("The public ip address of the server (" + serverPublicIP + ") is already in use in zone: " + dc.getName());
            }
        }
    }

    @Override
    public void deleteRoutingHost(final HostVO host, final boolean isForced, final boolean forceDestroyStorage) throws UnableDeleteHostException {
        if (host.getType() != Host.Type.Routing) {
            throw new CloudRuntimeException("Non-Routing host gets in deleteRoutingHost, id is " + host.getId());
        }

        if (s_logger.isDebugEnabled()) {
            s_logger.debug("Deleting Host: " + host.getId() + " Guid:" + host.getGuid());
        }

        if (forceDestroyStorage) {
            // put local storage into mainenance mode, will set all the VMs on
            // this local storage into stopped state
            final StoragePoolVO storagePool = _storageMgr.findLocalStorageOnHost(host.getId());
            if (storagePool != null) {
                if (storagePool.getStatus() == StoragePoolStatus.Up || storagePool.getStatus() == StoragePoolStatus.ErrorInMaintenance) {
                    try {
                        final StoragePool pool = _storageSvr.preparePrimaryStorageForMaintenance(storagePool.getId());
                        if (pool == null) {
                            s_logger.debug("Failed to set primary storage into maintenance mode");

                            throw new UnableDeleteHostException("Failed to set primary storage into maintenance mode");
                        }
                    } catch (final Exception e) {
                        s_logger.debug("Failed to set primary storage into maintenance mode, due to: " + e.toString());
                        throw new UnableDeleteHostException("Failed to set primary storage into maintenance mode, due to: " + e.toString());
                    }
                }

                final List<VMInstanceVO> vmsOnLocalStorage = _storageMgr.listByStoragePool(storagePool.getId());
                for (final VMInstanceVO vm : vmsOnLocalStorage) {
                    try {
                        _vmMgr.destroy(vm.getUuid());
                    } catch (final Exception e) {
                        final String errorMsg = "There was an error Destory the vm: " + vm + " as a part of hostDelete id=" + host.getId();
                        s_logger.debug(errorMsg, e);
                        throw new UnableDeleteHostException(errorMsg + "," + e.getMessage());
                    }
                }
            }
        } else {
            // Check if there are vms running/starting/stopping on this host
            final List<VMInstanceVO> vms = _vmDao.listByHostId(host.getId());
            if (!vms.isEmpty()) {
                if (isForced) {
                    // Stop HA disabled vms and HA enabled vms in Stopping state
                    // Restart HA enabled vms
                    for (final VMInstanceVO vm : vms) {
                        if (!vm.isHaEnabled() || vm.getState() == State.Stopping) {
                            s_logger.debug("Stopping vm: " + vm + " as a part of deleteHost id=" + host.getId());
                            try {
                                _vmMgr.advanceStop(vm.getUuid(), false);
                            } catch (final Exception e) {
                                final String errorMsg = "There was an error stopping the vm: " + vm + " as a part of hostDelete id=" + host.getId();
                                s_logger.debug(errorMsg, e);
                                throw new UnableDeleteHostException(errorMsg + "," + e.getMessage());
                            }
                        } else if (vm.isHaEnabled() && (vm.getState() == State.Running || vm.getState() == State.Starting)) {
                            s_logger.debug("Scheduling restart for vm: " + vm + " " + vm.getState() + " on the host id=" + host.getId());
                            _haMgr.scheduleRestart(vm, false);
                        }
                    }
                } else {
                    throw new UnableDeleteHostException("Unable to delete the host as there are vms in " + vms.get(0).getState() +
                            " state using this host and isForced=false specified");
                }
            }
        }
    }

    @Override
    public boolean executeUserRequest(final long hostId, final ResourceState.Event event) throws AgentUnavailableException {
        if (event == ResourceState.Event.AdminAskMaintenace) {
            return doMaintain(hostId);
        } else if (event == ResourceState.Event.AdminCancelMaintenance) {
            return doCancelMaintenance(hostId);
        } else if (event == ResourceState.Event.DeleteHost) {
      /* TODO: Ask alex why we assume the last two parameters are false */
            return doDeleteHost(hostId, false, false);
        } else if (event == ResourceState.Event.Unmanaged) {
            return doUmanageHost(hostId);
        } else if (event == ResourceState.Event.UpdatePassword) {
            return doUpdateHostPassword(hostId);
        } else {
            throw new CloudRuntimeException("Received an resource event we are not handling now, " + event);
        }
    }

    @Override
    public boolean resourceStateTransitTo(final Host host, final ResourceState.Event event, final long msId) throws NoTransitionException {
        final ResourceState currentState = host.getResourceState();
        final ResourceState nextState = currentState.getNextState(event);
        if (nextState == null) {
            throw new NoTransitionException("No next resource state found for current state = " + currentState + " event = " + event);
        }

        // TO DO - Make it more granular and have better conversion into capacity type
        if (host.getType() == Type.Routing) {
            final CapacityState capacityState = nextState == ResourceState.Enabled ? CapacityState.Enabled : CapacityState.Disabled;
            final short[] capacityTypes = {Capacity.CAPACITY_TYPE_CPU, Capacity.CAPACITY_TYPE_MEMORY};
            _capacityDao.updateCapacityState(null, null, null, host.getId(), capacityState.toString(), capacityTypes);
        }
        return _hostDao.updateResourceState(currentState, event, nextState, host);
    }

    @Override
    public boolean umanageHost(final long hostId) {
        try {
            final Boolean result = propagateResourceEvent(hostId, ResourceState.Event.Unmanaged);

            if (result != null) {
                return result;
            }
        } catch (final AgentUnavailableException e) {
            return false;
        }

        return doUmanageHost(hostId);
    }

    @Override
    public boolean maintenanceFailed(final long hostId) {
        final HostVO host = _hostDao.findById(hostId);
        if (host == null) {
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Cant not find host " + hostId);
            }
            return false;
        } else {
            try {
                return resourceStateTransitTo(host, ResourceState.Event.UnableToMigrate, _nodeId);
            } catch (final NoTransitionException e) {
                s_logger.debug("No next resource state for host " + host.getId() + " while current state is " + host.getResourceState() + " with event " +
                        ResourceState.Event.UnableToMigrate, e);
                return false;
            }
        }
    }

    @Override
    public boolean maintain(final long hostId) throws AgentUnavailableException {
        final Boolean result = propagateResourceEvent(hostId, ResourceState.Event.AdminAskMaintenace);
        if (result != null) {
            return result;
        }

        return doMaintain(hostId);
    }

    @Override
    public boolean checkAndMaintain(final long hostId) {
        boolean hostInMaintenance = false;
        final HostVO host = _hostDao.findById(hostId);

        try {
            if (host.getType() != Host.Type.Storage) {
                final List<VMInstanceVO> vos = _vmDao.listByHostId(hostId);
                final List<VMInstanceVO> vosMigrating = _vmDao.listVmsMigratingFromHost(hostId);
                if (vos.isEmpty() && vosMigrating.isEmpty()) {
                    resourceStateTransitTo(host, ResourceState.Event.InternalEnterMaintenance, _nodeId);
                    hostInMaintenance = true;
                    ActionEventUtils.onCompletedActionEvent(CallContext.current().getCallingUserId(), CallContext.current().getCallingAccountId(), EventVO.LEVEL_INFO, EventTypes
                            .EVENT_MAINTENANCE_PREPARE, "completed maintenance for host " + hostId, 0);
                }
            }
        } catch (final NoTransitionException e) {
            s_logger.debug("Cannot transmit host " + host.getId() + "to Maintenance state", e);
        }
        return hostInMaintenance;
    }

    @Override
    public boolean deleteHost(final long hostId, final boolean isForced, final boolean isForceDeleteStorage) {
        try {
            final Boolean result = propagateResourceEvent(hostId, ResourceState.Event.DeleteHost);
            if (result != null) {
                return result;
            }
        } catch (final AgentUnavailableException e) {
            return false;
        }

        return doDeleteHost(hostId, isForced, isForceDeleteStorage);
    }

    public Boolean propagateResourceEvent(final long agentId, final ResourceState.Event event) throws AgentUnavailableException {
        final String msPeer = getPeerName(agentId);
        if (msPeer == null) {
            return null;
        }

        if (s_logger.isDebugEnabled()) {
            s_logger.debug("Propagating agent change request event:" + event.toString() + " to agent:" + agentId);
        }
        final Command[] cmds = new Command[1];
        cmds[0] = new PropagateResourceEventCommand(agentId, event);

        final String AnsStr = _clusterMgr.execute(msPeer, agentId, _gson.toJson(cmds), true);
        if (AnsStr == null) {
            throw new AgentUnavailableException(agentId);
        }

        final Answer[] answers = _gson.fromJson(AnsStr, Answer[].class);

        if (s_logger.isDebugEnabled()) {
            s_logger.debug("Result for agent change is " + answers[0].getResult());
        }

        return answers[0].getResult();
    }

    public String getPeerName(final long agentHostId) {

        final HostVO host = _hostDao.findById(agentHostId);
        if (host != null && host.getManagementServerId() != null) {
            if (_clusterMgr.getSelfPeerName().equals(Long.toString(host.getManagementServerId()))) {
                return null;
            }

            return Long.toString(host.getManagementServerId());
        }
        return null;
    }

    @Override
    public List<HostVO> findDirectlyConnectedHosts() {
    /* The resource column is not null for direct connected resource */
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        sc.and(sc.entity().getResource(), Op.NNULL);
        sc.and(sc.entity().getResourceState(), Op.NIN, ResourceState.Disabled);
        return sc.list();
    }

    @Override
    public List<HostVO> listAllUpAndEnabledHosts(final Type type, final Long clusterId, final Long podId, final long dcId) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        if (type != null) {
            sc.and(sc.entity().getType(), Op.EQ, type);
        }
        if (clusterId != null) {
            sc.and(sc.entity().getClusterId(), Op.EQ, clusterId);
        }
        if (podId != null) {
            sc.and(sc.entity().getPodId(), Op.EQ, podId);
        }
        sc.and(sc.entity().getDataCenterId(), Op.EQ, dcId);
        sc.and(sc.entity().getStatus(), Op.EQ, Status.Up);
        sc.and(sc.entity().getResourceState(), Op.EQ, ResourceState.Enabled);
        return sc.list();
    }

    @Override
    public List<HostVO> listAllHostsInCluster(final long clusterId) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        sc.and(sc.entity().getClusterId(), Op.EQ, clusterId);
        return sc.list();
    }

    @Override
    public List<HostVO> listHostsInClusterByStatus(final long clusterId, final Status status) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        sc.and(sc.entity().getClusterId(), Op.EQ, clusterId);
        sc.and(sc.entity().getStatus(), Op.EQ, status);
        return sc.list();
    }

    @Override
    public List<HostVO> listAllUpAndEnabledHostsInOneZoneByType(final Type type, final long dcId) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        sc.and(sc.entity().getType(), Op.EQ, type);
        sc.and(sc.entity().getDataCenterId(), Op.EQ, dcId);
        sc.and(sc.entity().getStatus(), Op.EQ, Status.Up);
        sc.and(sc.entity().getResourceState(), Op.EQ, ResourceState.Enabled);
        return sc.list();
    }

    @Override
    public List<HostVO> listAllUpAndEnabledHostsInOneZoneByHypervisor(final HypervisorType type, final long dcId) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        sc.and(sc.entity().getHypervisorType(), Op.EQ, type);
        sc.and(sc.entity().getDataCenterId(), Op.EQ, dcId);
        sc.and(sc.entity().getStatus(), Op.EQ, Status.Up);
        sc.and(sc.entity().getResourceState(), Op.EQ, ResourceState.Enabled);
        return sc.list();
    }

    @Override
    public List<HostVO> listAllUpAndEnabledHostsInOneZone(final long dcId) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);

        sc.and(sc.entity().getDataCenterId(), Op.EQ, dcId);
        sc.and(sc.entity().getStatus(), Op.EQ, Status.Up);
        sc.and(sc.entity().getResourceState(), Op.EQ, ResourceState.Enabled);

        return sc.list();
    }

    @Override
    public List<HostVO> listAllHostsInOneZoneByType(final Type type, final long dcId) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        sc.and(sc.entity().getType(), Op.EQ, type);
        sc.and(sc.entity().getDataCenterId(), Op.EQ, dcId);
        return sc.list();
    }

    @Override
    public List<HostVO> listAllHostsInAllZonesByType(final Type type) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        sc.and(sc.entity().getType(), Op.EQ, type);
        return sc.list();
    }

    @Override
    public List<HypervisorType> listAvailHypervisorInZone(final Long hostId, final Long zoneId) {
        final SearchCriteria<String> sc = _hypervisorsInDC.create();
        if (zoneId != null) {
            sc.setParameters("dataCenter", zoneId);
        }
        if (hostId != null) {
            // exclude the given host, since we want to check what hypervisor is already handled
            // in adding this new host
            sc.setParameters("id", hostId);
        }
        sc.setParameters("type", Host.Type.Routing);

        // The search is not able to return list of enums, so getting
        // list of hypervisors as strings and then converting them to enum
        final List<String> hvs = _hostDao.customSearch(sc, null);
        final List<HypervisorType> hypervisors = new ArrayList<>();
        for (final String hv : hvs) {
            hypervisors.add(HypervisorType.getType(hv));
        }
        return hypervisors;
    }

    @Override
    public HostVO findHostByGuid(final String guid) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        sc.and(sc.entity().getGuid(), Op.EQ, guid);
        return sc.find();
    }

    @Override
    public HostVO findHostByName(final String name) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        sc.and(sc.entity().getName(), Op.EQ, name);
        return sc.find();
    }

    @Override
    public HostStats getHostStatistics(final long hostId) {
        final Answer answer = _agentMgr.easySend(hostId, new GetHostStatsCommand(_hostDao.findById(hostId).getGuid(), _hostDao.findById(hostId).getName(), hostId));

        if (answer != null && answer instanceof UnsupportedAnswer) {
            return null;
        }

        if (answer == null || !answer.getResult()) {
            final String msg = "Unable to obtain host " + hostId + " statistics. ";
            s_logger.warn(msg);
            return null;
        } else {

            // now construct the result object
            if (answer instanceof GetHostStatsAnswer) {
                return ((GetHostStatsAnswer) answer).getHostStats();
            }
        }
        return null;
    }

    @Override
    public Long getGuestOSCategoryId(final long hostId) {
        final HostVO host = _hostDao.findById(hostId);
        if (host == null) {
            return null;
        } else {
            _hostDao.loadDetails(host);
            final DetailVO detail = _hostDetailsDao.findDetail(hostId, "guest.os.category.id");
            if (detail == null) {
                return null;
            } else {
                return Long.parseLong(detail.getValue());
            }
        }
    }

    @Override
    public String getHostTags(final long hostId) {
        final List<String> hostTags = _hostTagsDao.gethostTags(hostId);
        if (hostTags == null) {
            return null;
        } else {
            return StringUtils.listToCsvTags(hostTags);
        }
    }

    @Override
    public List<PodCluster> listByDataCenter(final long dcId) {
        final List<HostPodVO> pods = _podDao.listByDataCenterId(dcId);
        final ArrayList<PodCluster> pcs = new ArrayList<>();
        for (final HostPodVO pod : pods) {
            final List<ClusterVO> clusters = _clusterDao.listByPodId(pod.getId());
            if (clusters.size() == 0) {
                pcs.add(new PodCluster(pod, null));
            } else {
                for (final ClusterVO cluster : clusters) {
                    pcs.add(new PodCluster(pod, cluster));
                }
            }
        }
        return pcs;
    }

    @Override
    public List<HostVO> listAllNotInMaintenanceHostsInOneZone(final Type type, final Long dcId) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        if (dcId != null) {
            sc.and(sc.entity().getDataCenterId(), Op.EQ, dcId);
        }
        sc.and(sc.entity().getType(), Op.EQ, type);
        sc.and(sc.entity().getResourceState(), Op.NIN, ResourceState.Maintenance, ResourceState.ErrorInMaintenance, ResourceState.PrepareForMaintenance,
                ResourceState.Error);
        return sc.list();
    }

    @Override
    public HypervisorType getDefaultHypervisor(final long zoneId) {
        HypervisorType defaultHyper = HypervisorType.None;
        if (_defaultSystemVMHypervisor != HypervisorType.None) {
            defaultHyper = _defaultSystemVMHypervisor;
        }

        final DataCenterVO dc = _dcDao.findById(zoneId);
        if (dc == null) {
            return HypervisorType.None;
        }
        _dcDao.loadDetails(dc);
        final String defaultHypervisorInZone = dc.getDetail("defaultSystemVMHypervisorType");
        if (defaultHypervisorInZone != null) {
            defaultHyper = HypervisorType.getType(defaultHypervisorInZone);
        }

        final List<VMTemplateVO> systemTemplates = _templateDao.listAllSystemVMTemplates();
        boolean isValid = false;
        for (final VMTemplateVO template : systemTemplates) {
            if (template.getHypervisorType() == defaultHyper) {
                isValid = true;
                break;
            }
        }

        if (isValid) {
            final List<ClusterVO> clusters = _clusterDao.listByDcHyType(zoneId, defaultHyper.toString());
            if (clusters.size() <= 0) {
                isValid = false;
            }
        }

        if (isValid) {
            return defaultHyper;
        } else {
            return HypervisorType.None;
        }
    }

    @Override
    public HypervisorType getAvailableHypervisor(final long zoneId) {
        HypervisorType defaultHype = getDefaultHypervisor(zoneId);
        if (defaultHype == HypervisorType.None) {
            final List<HypervisorType> supportedHypes = getSupportedHypervisorTypes(zoneId, false, null);
            if (supportedHypes.size() > 0) {
                Collections.shuffle(supportedHypes);
                defaultHype = supportedHypes.get(0);
            }
        }

        if (defaultHype == HypervisorType.None) {
            defaultHype = HypervisorType.Any;
        }
        return defaultHype;
    }

    @Override
    public Discoverer getMatchingDiscover(final Hypervisor.HypervisorType hypervisorType) {
        for (final Discoverer discoverer : _discoverers) {
            if (discoverer.getHypervisorType() == hypervisorType) {
                return discoverer;
            }
        }
        return null;
    }

    @Override
    public List<HostVO> findHostByGuid(final long dcId, final String guid) {
        final QueryBuilder<HostVO> sc = QueryBuilder.create(HostVO.class);
        sc.and(sc.entity().getDataCenterId(), Op.EQ, dcId);
        sc.and(sc.entity().getGuid(), Op.EQ, guid);
        return sc.list();
    }

    @Override
    public List<HostVO> listAllUpAndEnabledNonHAHosts(final Type type, final Long clusterId, final Long podId, final long dcId) {
        final String haTag = _haMgr.getHaTag();
        return _hostDao.listAllUpAndEnabledNonHAHosts(type, clusterId, podId, dcId, haTag);
    }

    @Override
    public boolean isHostGpuEnabled(final long hostId) {
        final SearchCriteria<HostGpuGroupsVO> sc = _gpuAvailability.create();
        sc.setParameters("hostId", hostId);
        return _hostGpuGroupsDao.customSearch(sc, null).size() > 0;
    }

    @Override
    public boolean isGPUDeviceAvailable(final long hostId, final String groupName, final String vgpuType) {
        if (!listAvailableGPUDevice(hostId, groupName, vgpuType).isEmpty()) {
            return true;
        } else {
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Host ID: " + hostId + " does not have GPU device available");
            }
            return false;
        }
    }

    @Override
    public GPUDeviceTO getGPUDevice(final long hostId, final String groupName, final String vgpuType) {
        final HostGpuGroupsVO gpuDevice = listAvailableGPUDevice(hostId, groupName, vgpuType).get(0);
        return new GPUDeviceTO(gpuDevice.getGroupName(), vgpuType, null);
    }

    @Override
    public List<HostGpuGroupsVO> listAvailableGPUDevice(final long hostId, final String groupName, final String vgpuType) {
        final Filter searchFilter = new Filter(VGPUTypesVO.class, "remainingCapacity", false, null, null);
        final SearchCriteria<HostGpuGroupsVO> sc = _gpuAvailability.create();
        sc.setParameters("hostId", hostId);
        sc.setParameters("groupName", groupName);
        sc.setJoinParameters("groupId", "vgpuType", vgpuType);
        sc.setJoinParameters("groupId", "remainingCapacity", 0);
        return _hostGpuGroupsDao.customSearch(sc, searchFilter);
    }

    @Override
    public void updateGPUDetails(final long hostId, final HashMap<String, HashMap<String, VgpuTypesInfo>> groupDetails) {
        // Update GPU group capacity
        final TransactionLegacy txn = TransactionLegacy.currentTxn();
        txn.start();
        _hostGpuGroupsDao.persist(hostId, new ArrayList<>(groupDetails.keySet()));
        _vgpuTypesDao.persist(hostId, groupDetails);
        txn.commit();
    }

    @Override
    public HashMap<String, HashMap<String, VgpuTypesInfo>> getGPUStatistics(final HostVO host) {
        final Answer answer = _agentMgr.easySend(host.getId(), new GetGPUStatsCommand(host.getGuid(), host.getName()));
        if (answer != null && answer instanceof UnsupportedAnswer) {
            return null;
        }
        if (answer == null || !answer.getResult()) {
            final String msg = "Unable to obtain GPU stats for host " + host.getName();
            s_logger.warn(msg);
            return null;
        } else {
            // now construct the result object
            if (answer instanceof GetGPUStatsAnswer) {
                return ((GetGPUStatsAnswer) answer).getGroupDetails();
            }
        }
        return null;
    }

    private boolean doMaintain(final long hostId) {
        final HostVO host = _hostDao.findById(hostId);
        final MaintainAnswer answer = (MaintainAnswer) _agentMgr.easySend(hostId, new MaintainCommand());
        if (answer == null || !answer.getResult()) {
            s_logger.warn("Unable to send MaintainCommand to host: " + hostId);
            return false;
        }

        try {
            resourceStateTransitTo(host, ResourceState.Event.AdminAskMaintenace, _nodeId);
        } catch (final NoTransitionException e) {
            final String err = "Cannot transmit resource state of host " + host.getId() + " to " + ResourceState.Maintenance;
            s_logger.debug(err, e);
            throw new CloudRuntimeException(err + e.getMessage());
        }

        ActionEventUtils.onStartedActionEvent(CallContext.current().getCallingUserId(), CallContext.current().getCallingAccountId(), EventTypes.EVENT_MAINTENANCE_PREPARE,
                "starting maintenance for host " + hostId, true, 0);
        _agentMgr.pullAgentToMaintenance(hostId);

    /* TODO: move below to listener */
        if (host.getType() == Host.Type.Routing) {

            final List<VMInstanceVO> vms = _vmDao.listByHostId(hostId);
            if (vms.size() == 0) {
                return true;
            }

            final List<HostVO> hosts = listAllUpAndEnabledHosts(Host.Type.Routing, host.getClusterId(), host.getPodId(), host.getDataCenterId());
            for (final VMInstanceVO vm : vms) {
                if (hosts == null || hosts.isEmpty() || !answer.getMigrate()
                        || _serviceOfferingDetailsDao.findDetail(vm.getServiceOfferingId(), GPU.Keys.vgpuType.toString()) != null) {
                    // Migration is not supported for VGPU Vms so stop them.
                    // for the last host in this cluster, stop all the VMs
                    _haMgr.scheduleStop(vm, hostId, WorkType.ForceStop);
                } else {
                    _haMgr.scheduleMigration(vm);
                }
            }
        }
        return true;
    }

    private boolean doCancelMaintenance(final long hostId) {
        final HostVO host;
        host = _hostDao.findById(hostId);
        if (host == null || host.getRemoved() != null) {
            s_logger.warn("Unable to find host " + hostId);
            return true;
        }

    /*
     * TODO: think twice about returning true or throwing out exception, I
     * really prefer to exception that always exposes bugs
     */
        if (host.getResourceState() != ResourceState.PrepareForMaintenance && host.getResourceState() != ResourceState.Maintenance &&
                host.getResourceState() != ResourceState.ErrorInMaintenance) {
            throw new CloudRuntimeException("Cannot perform cancelMaintenance when resource state is " + host.getResourceState() + ", hostId = " + hostId);
        }

    /* TODO: move to listener */
        _haMgr.cancelScheduledMigrations(host);

        boolean vms_migrating = false;
        final List<VMInstanceVO> vms = _haMgr.findTakenMigrationWork();
        for (final VMInstanceVO vm : vms) {
            if (vm.getHostId() != null && vm.getHostId() == hostId) {
                s_logger.warn("Unable to cancel migration because the vm is being migrated: " + vm + ", hostId = " + hostId);
                vms_migrating = true;
            }
        }

        try {
            resourceStateTransitTo(host, ResourceState.Event.AdminCancelMaintenance, _nodeId);
            _agentMgr.pullAgentOutMaintenance(hostId);

            // for kvm, need to log into kvm host, restart cosmic-agent
            if ((host.getHypervisorType() == HypervisorType.KVM && !vms_migrating)) {

                final boolean sshToAgent = Boolean.parseBoolean(_configDao.getValue(Config.KvmSshToAgentEnabled.key()));
                if (!sshToAgent) {
                    s_logger.info("Configuration tells us not to SSH into Agents. Please restart the Agent (" + hostId + ")  manually");
                    return true;
                }

                _hostDao.loadDetails(host);
                final String password = host.getDetail("password");
                final String username = host.getDetail("username");
                if (password == null || username == null) {
                    s_logger.debug("Can't find password/username");
                    return false;
                }
                final com.trilead.ssh2.Connection connection = SSHCmdHelper.acquireAuthorizedConnection(host.getPrivateIpAddress(), 22, username, password);
                if (connection == null) {
                    s_logger.debug("Failed to connect to host: " + host.getPrivateIpAddress());
                    return false;
                }

                try {
                    SSHCmdHelper.sshExecuteCmdOneShot(connection, "systemctl restart cosmic-agent");
                } catch (final SshException e) {
                    s_logger.info("Tried to restart agent but it failed. Please restart the Agent (" + hostId + ")  manually");
                    // We return true here because cancel maintenance works fine even without restarting the agent
                    // No need to send an error.
                    return true;
                }
            }

            return true;
        } catch (final NoTransitionException e) {
            s_logger.debug("Cannot transmit host " + host.getId() + "to Enabled state", e);
            return false;
        }
    }

    @DB
    protected boolean doDeleteHost(final long hostId, final boolean isForced, final boolean isForceDeleteStorage) {
        _accountMgr.getActiveUser(CallContext.current().getCallingUserId());
        // Verify that host exists
        final HostVO host = _hostDao.findById(hostId);
        if (host == null) {
            throw new InvalidParameterValueException("Host with id " + hostId + " doesn't exist");
        }
        _accountMgr.checkAccessAndSpecifyAuthority(CallContext.current().getCallingAccount(), host.getDataCenterId());

        if (!isForced && host.getResourceState() != ResourceState.Maintenance) {
            throw new CloudRuntimeException("Host " + host.getUuid() +
                    " cannot be deleted as it is not in maintenance mode. Either put the host into maintenance or perform a forced deletion.");
        }
        // Get storage pool host mappings here because they can be removed as a
        // part of handleDisconnect later
        // TODO: find out the bad boy, what's a buggy logic!
        final List<StoragePoolHostVO> pools = _storagePoolHostDao.listByHostIdIncludingRemoved(hostId);

        final ResourceStateAdapter.DeleteHostAnswer answer =
                (ResourceStateAdapter.DeleteHostAnswer) dispatchToStateAdapters(ResourceStateAdapter.Event.DELETE_HOST, false, host, isForced,
                        isForceDeleteStorage);

        if (answer == null) {
            throw new CloudRuntimeException("No resource adapter respond to DELETE_HOST event for " + host.getName() + " id = " + hostId + ", hypervisorType is " +
                    host.getHypervisorType() + ", host type is " + host.getType());
        }

        if (answer.getIsException()) {
            return false;
        }

        if (!answer.getIsContinue()) {
            return true;
        }

        Transaction.execute(new TransactionCallbackNoReturn() {
            @Override
            public void doInTransactionWithoutResult(final TransactionStatus status) {

                _dcDao.releasePrivateIpAddress(host.getPrivateIpAddress(), host.getDataCenterId(), null);
                _agentMgr.disconnectWithoutInvestigation(hostId, Status.Event.Remove);

                // delete host details
                _hostDetailsDao.deleteDetails(hostId);

                // if host is GPU enabled, delete GPU entries
                _hostGpuGroupsDao.deleteGpuEntries(hostId);

                // delete host tags
                _hostTagsDao.deleteTags(hostId);

                host.setGuid(null);
                final Long clusterId = host.getClusterId();
                host.setClusterId(null);
                _hostDao.update(host.getId(), host);

                _hostDao.remove(hostId);
                if (clusterId != null) {
                    final List<HostVO> hosts = listAllHostsInCluster(clusterId);
                    if (hosts.size() == 0) {
                        final ClusterVO cluster = _clusterDao.findById(clusterId);
                        cluster.setGuid(null);
                        _clusterDao.update(clusterId, cluster);
                    }
                }

                try {
                    resourceStateTransitTo(host, ResourceState.Event.DeleteHost, _nodeId);
                } catch (final NoTransitionException e) {
                    s_logger.debug("Cannot transmit host " + host.getId() + " to Enabled state", e);
                }

                // Delete the associated entries in host ref table
                _storagePoolHostDao.deletePrimaryRecordsForHost(hostId);

                // Make sure any VMs that were marked as being on this host are cleaned up
                final List<VMInstanceVO> vms = _vmDao.listByHostId(hostId);
                for (final VMInstanceVO vm : vms) {
                    // this is how VirtualMachineManagerImpl does it when it syncs VM states
                    vm.setState(State.Stopped);
                    vm.setHostId(null);
                    _vmDao.persist(vm);
                }

                // For pool ids you got, delete local storage host entries in pool table
                // where
                for (final StoragePoolHostVO pool : pools) {
                    final Long poolId = pool.getPoolId();
                    final StoragePoolVO storagePool = _storagePoolDao.findById(poolId);
                    if (storagePool.isLocal() && isForceDeleteStorage) {
                        storagePool.setUuid(null);
                        storagePool.setClusterId(null);
                        _storagePoolDao.update(poolId, storagePool);
                        _storagePoolDao.remove(poolId);
                        s_logger.debug("Local storage id=" + poolId + " is removed as a part of host removal id=" + hostId);
                    }
                }

                // delete the op_host_capacity entry
                final Object[] capacityTypes = {Capacity.CAPACITY_TYPE_CPU, Capacity.CAPACITY_TYPE_MEMORY};
                final SearchCriteria<CapacityVO> hostCapacitySC = _capacityDao.createSearchCriteria();
                hostCapacitySC.addAnd("hostOrPoolId", SearchCriteria.Op.EQ, hostId);
                hostCapacitySC.addAnd("capacityType", SearchCriteria.Op.IN, capacityTypes);
                _capacityDao.remove(hostCapacitySC);
                // remove from dedicated resources
                final DedicatedResourceVO dr = _dedicatedDao.findByHostId(hostId);
                if (dr != null) {
                    _dedicatedDao.remove(dr.getId());
                }
            }
        });

        return true;
    }

    private boolean doUmanageHost(final long hostId) {
        final HostVO host = _hostDao.findById(hostId);
        if (host == null) {
            s_logger.debug("Cannot find host " + hostId + ", assuming it has been deleted, skip umanage");
            return true;
        }

        if (host.getHypervisorType() == HypervisorType.KVM) {
            _agentMgr.easySend(hostId, new MaintainCommand());
        }

        _agentMgr.disconnectWithoutInvestigation(hostId, Event.ShutdownRequested);
        return true;
    }

    private boolean doUpdateHostPassword(final long hostId) {
        if (!_agentMgr.isAgentAttached(hostId)) {
            return false;
        }

        DetailVO nv = _hostDetailsDao.findDetail(hostId, ApiConstants.USERNAME);
        final String username = nv.getValue();
        nv = _hostDetailsDao.findDetail(hostId, ApiConstants.PASSWORD);
        final String password = nv.getValue();

        final HostVO host = _hostDao.findById(hostId);
        final String hostIpAddress = host.getPrivateIpAddress();

        final UpdateHostPasswordCommand cmd = new UpdateHostPasswordCommand(username, password, hostIpAddress);
        final Answer answer = _agentMgr.easySend(hostId, cmd);

        s_logger.info("Result returned from update host password ==> " + answer.getDetails());
        return answer.getResult();
    }

    private Host createHostAndAgent(final ServerResource resource, final Map<String, String> details, final boolean old, final List<String> hostTags, final boolean forRebalance) {
        HostVO host = null;
        StartupCommand[] cmds = null;
        boolean hostExists = false;
        boolean created = false;

        try {
            cmds = resource.initialize();
            if (cmds == null) {
                s_logger.info("Unable to fully initialize the agent because no StartupCommands are returned");
                return null;
            }

      /* Generate a random version in a dev setup situation */
            if (this.getClass().getPackage().getImplementationVersion() == null) {
                for (final StartupCommand cmd : cmds) {
                    if (cmd.getVersion() == null) {
                        cmd.setVersion(Long.toString(System.currentTimeMillis()));
                    }
                }
            }

            if (s_logger.isDebugEnabled()) {
                new Request(-1l, -1l, cmds, true, false).logD("Startup request from directly connected host: ", true);
            }

            if (old) {
                final StartupCommand firstCmd = cmds[0];
                host = findHostByGuid(firstCmd.getGuid());
                if (host == null) {
                    host = findHostByGuid(firstCmd.getGuidWithoutResource());
                }
                if (host != null && host.getRemoved() == null) { // host already added, no need to add again
                    s_logger.debug("Found the host " + host.getId() + " by guid: " + firstCmd.getGuid() + ", old host reconnected as new");
                    hostExists = true; // ensures that host status is left unchanged in case of adding same one again
                    return null;
                }
            }

            host = createHostVO(cmds, resource, details, hostTags, ResourceStateAdapter.Event.CREATE_HOST_VO_FOR_DIRECT_CONNECT);
            if (host != null) {
                created = _agentMgr.handleDirectConnectAgent(host, cmds, resource, forRebalance);
        /* reload myself from database */
                host = _hostDao.findById(host.getId());
            }
        } catch (final Exception e) {
            s_logger.warn("Unable to connect due to ", e);
        } finally {
            if (hostExists) {
                if (cmds != null) {
                    resource.disconnected();
                }
            } else {
                if (!created) {
                    if (cmds != null) {
                        resource.disconnected();
                    }
                    markHostAsDisconnected(host, cmds);
                }
            }
        }

        return host;
    }

    protected HostVO createHostVO(final StartupCommand[] cmds, final ServerResource resource, final Map<String, String> details, List<String> hostTags,
                                  final ResourceStateAdapter.Event stateEvent) {
        final StartupCommand startup = cmds[0];
        HostVO host = findHostByGuid(startup.getGuid());
        boolean isNew = false;
        if (host == null) {
            host = findHostByGuid(startup.getGuidWithoutResource());
        }
        if (host == null) {
            host = new HostVO(startup.getGuid());
            isNew = true;
        }

        String dataCenter = startup.getDataCenter();
        String pod = startup.getPod();
        final String cluster = startup.getCluster();

        if (pod != null && dataCenter != null && pod.equalsIgnoreCase("default") && dataCenter.equalsIgnoreCase("default")) {
            final List<HostPodVO> pods = _podDao.listAllIncludingRemoved();
            for (final HostPodVO hpv : pods) {
                if (checkCIDR(hpv, startup.getPrivateIpAddress(), startup.getPrivateNetmask())) {
                    pod = hpv.getName();
                    dataCenter = _dcDao.findById(hpv.getDataCenterId()).getName();
                    break;
                }
            }
        }

        long dcId;
        DataCenterVO dc = _dcDao.findByName(dataCenter);
        if (dc == null) {
            try {
                dcId = Long.parseLong(dataCenter);
                dc = _dcDao.findById(dcId);
            } catch (final NumberFormatException e) {
                s_logger.debug("Cannot parse " + dataCenter + " into Long.");
            }
        }
        if (dc == null) {
            throw new IllegalArgumentException("Host " + startup.getPrivateIpAddress() + " sent incorrect data center: " + dataCenter);
        }
        dcId = dc.getId();

        HostPodVO p = _podDao.findByName(pod, dcId);
        if (p == null) {
            try {
                final long podId = Long.parseLong(pod);
                p = _podDao.findById(podId);
            } catch (final NumberFormatException e) {
                s_logger.debug("Cannot parse " + pod + " into Long.");
            }
        }
    /*
     * ResourceStateAdapter is responsible for throwing Exception if Pod is
     * null and non-null is required. for example, XcpServerDiscoever.
     */
        final Long podId = p == null ? null : p.getId();

        Long clusterId = null;
        if (cluster != null) {
            try {
                clusterId = Long.valueOf(cluster);
            } catch (final NumberFormatException e) {
                if (podId != null) {
                    ClusterVO c = _clusterDao.findBy(cluster, podId.longValue());
                    if (c == null) {
                        c = new ClusterVO(dcId, podId.longValue(), cluster);
                        c = _clusterDao.persist(c);
                    }
                    clusterId = c.getId();
                }
            }
        }

        if (startup instanceof StartupRoutingCommand) {
            final StartupRoutingCommand ssCmd = (StartupRoutingCommand) startup;
            final List<String> implicitHostTags = ssCmd.getHostTags();
            if (!implicitHostTags.isEmpty()) {
                if (hostTags == null) {
                    hostTags = _hostTagsDao.gethostTags(host.getId());
                }
                if (hostTags != null) {
                    implicitHostTags.removeAll(hostTags);
                    hostTags.addAll(implicitHostTags);
                } else {
                    hostTags = implicitHostTags;
                }
            }
        }

        host.setDataCenterId(dc.getId());
        host.setPodId(podId);
        host.setClusterId(clusterId);
        host.setPrivateIpAddress(startup.getPrivateIpAddress());
        host.setPrivateNetmask(startup.getPrivateNetmask());
        host.setPrivateMacAddress(startup.getPrivateMacAddress());
        host.setPublicIpAddress(startup.getPublicIpAddress());
        host.setPublicMacAddress(startup.getPublicMacAddress());
        host.setPublicNetmask(startup.getPublicNetmask());
        host.setStorageIpAddress(startup.getStorageIpAddress());
        host.setStorageMacAddress(startup.getStorageMacAddress());
        host.setStorageNetmask(startup.getStorageNetmask());
        host.setVersion(startup.getVersion());
        host.setName(startup.getName());
        host.setManagementServerId(_nodeId);
        host.setStorageUrl(startup.getIqn());
        host.setLastPinged(System.currentTimeMillis() >> 10);
        host.setHostTags(hostTags);
        host.setDetails(details);
        if (startup.getStorageIpAddressDeux() != null) {
            host.setStorageIpAddressDeux(startup.getStorageIpAddressDeux());
            host.setStorageMacAddressDeux(startup.getStorageMacAddressDeux());
            host.setStorageNetmaskDeux(startup.getStorageNetmaskDeux());
        }
        if (resource != null) {
      /* null when agent is connected agent */
            host.setResource(resource.getClass().getName());
        }

        host = (HostVO) dispatchToStateAdapters(stateEvent, true, host, cmds, resource, details, hostTags);
        if (host == null) {
            throw new CloudRuntimeException("No resource state adapter response");
        }

        if (isNew) {
            host = _hostDao.persist(host);
        } else {
            _hostDao.update(host.getId(), host);
        }

        try {
            resourceStateTransitTo(host, ResourceState.Event.InternalCreated, _nodeId);
      /* Agent goes to Connecting status */
            _agentMgr.agentStatusTransitTo(host, Status.Event.AgentConnected, _nodeId);
        } catch (final Exception e) {
            s_logger.debug("Cannot transmit host " + host.getId() + " to Creating state", e);
            _agentMgr.agentStatusTransitTo(host, Status.Event.Error, _nodeId);
            try {
                resourceStateTransitTo(host, ResourceState.Event.Error, _nodeId);
            } catch (final NoTransitionException e1) {
                s_logger.debug("Cannot transmit host " + host.getId() + "to Error state", e);
            }
        }

        return host;
    }

    private void markHostAsDisconnected(HostVO host, final StartupCommand[] cmds) {
        if (host == null) { // in case host is null due to some errors, try
            // reloading the host from db
            if (cmds != null) {
                final StartupCommand firstCmd = cmds[0];
                host = findHostByGuid(firstCmd.getGuid());
                if (host == null) {
                    host = findHostByGuid(firstCmd.getGuidWithoutResource());
                }
            }
        }

        if (host != null) {
            // Change agent status to Alert, so that host is considered for
            // reconnection next time
            _agentMgr.agentStatusTransitTo(host, Status.Event.AgentDisconnected, _nodeId);
        }
    }

    private boolean checkCIDR(final HostPodVO pod, final String serverPrivateIP, final String serverPrivateNetmask) {
        if (serverPrivateIP == null) {
            return true;
        }
        // Get the CIDR address and CIDR size
        final String cidrAddress = pod.getCidrAddress();
        final long cidrSize = pod.getCidrSize();

        // If the server's private IP address is not in the same subnet as the
        // pod's CIDR, return false
        final String cidrSubnet = NetUtils.getCidrSubNet(cidrAddress, cidrSize);
        final String serverSubnet = NetUtils.getSubNet(serverPrivateIP, serverPrivateNetmask);
        if (!cidrSubnet.equals(serverSubnet)) {
            return false;
        }

        // If the server's private netmask is less inclusive than the pod's CIDR
        // netmask, return false
        final String cidrNetmask = NetUtils.getCidrSubNet("255.255.255.255", cidrSize);
        final long cidrNetmaskNumeric = NetUtils.ip2Long(cidrNetmask);
        final long serverNetmaskNumeric = NetUtils.ip2Long(serverPrivateNetmask);
        return serverNetmaskNumeric <= cidrNetmaskNumeric;
    }

    private Object dispatchToStateAdapters(final ResourceStateAdapter.Event event, final boolean singleTaker, final Object... args) {
        synchronized (_resourceStateAdapters) {
            final Iterator<Map.Entry<String, ResourceStateAdapter>> it = _resourceStateAdapters.entrySet().iterator();
            Object result = null;
            while (it.hasNext()) {
                final Map.Entry<String, ResourceStateAdapter> item = it.next();
                final ResourceStateAdapter adapter = item.getValue();

                final String msg = "Dispatching resource state event " + event + " to " + item.getKey();
                s_logger.debug(msg);

                if (event == ResourceStateAdapter.Event.CREATE_HOST_VO_FOR_CONNECTED) {
                    result = adapter.createHostVOForConnectedAgent((HostVO) args[0], (StartupCommand[]) args[1]);
                    if (result != null && singleTaker) {
                        break;
                    }
                } else if (event == ResourceStateAdapter.Event.CREATE_HOST_VO_FOR_DIRECT_CONNECT) {
                    result =
                            adapter.createHostVOForDirectConnectAgent((HostVO) args[0], (StartupCommand[]) args[1], (ServerResource) args[2], (Map<String, String>) args[3],
                                    (List<String>) args[4]);
                    if (result != null && singleTaker) {
                        break;
                    }
                } else if (event == ResourceStateAdapter.Event.DELETE_HOST) {
                    try {
                        result = adapter.deleteHost((HostVO) args[0], (Boolean) args[1], (Boolean) args[2]);
                        if (result != null) {
                            break;
                        }
                    } catch (final UnableDeleteHostException e) {
                        s_logger.debug("Adapter " + adapter.getName() + " says unable to delete host", e);
                        result = new ResourceStateAdapter.DeleteHostAnswer(false, true);
                    }
                } else {
                    throw new CloudRuntimeException("Unknown resource state event:" + event);
                }
            }

            return result;
        }
    }

    private List<HostVO> discoverHostsFull(final Long dcId, final Long podId, Long clusterId, final String clusterName, final String url, final String username, final String
            password,
                                           final String hypervisorType, final List<String> hostTags, final Map<String, String> params, final boolean deferAgentCreation) throws
            IllegalArgumentException, DiscoveryException,
            InvalidParameterValueException {
        final ResourceChecker resourceChecker = ResourceChecker.builder()
                                                               .dataCenterDao(_dcDao)
                                                               .accountManager(_accountMgr)
                                                               .hostPodDao(_podDao)
                                                               .build();
        s_logger.info("Trying to discover host for " + hypervisorType);
        final DataCenterVO zone = resourceChecker.checkIfDataCenterExists(dcId);
        final Account account = CallContext.current().getCallingAccount();
        resourceChecker.checkIfDataCenterIsUsable(zone, account);
        final HostPodVO pod = resourceChecker.checkIfPodExists(podId);
        resourceChecker.checkIfPodIsUsable(zone, pod);

        verifyClusterInfo(podId, clusterId, clusterName, hypervisorType);
        clusterId = getOrCreateCluster(zone, pod, clusterId, clusterName, hypervisorType);

        final URI uri = generateUri(url);

        final List<HostVO> hosts = new ArrayList<>();
        s_logger.info("Trying to add a new host at " + url + " in data center " + dcId);
        boolean isHypervisorTypeSupported = false;
        for (final Discoverer discoverer : _discoverers) {
            if (params != null) {
                discoverer.putParam(params);
            }

            if (!discoverer.matchHypervisor(hypervisorType)) {
                s_logger.debug("Discoverer " + discoverer.getName() + " for " + discoverer.getHypervisorType() + " is not a match for " + hypervisorType);
                continue;
            }
            s_logger.debug("Discoverer " + discoverer.getName() + " for " + discoverer.getHypervisorType() + " is a match for " + hypervisorType);
            isHypervisorTypeSupported = true;
            Map<? extends ServerResource, Map<String, String>> resources = null;

            processResourceEvent(ResourceListener.EVENT_DISCOVER_BEFORE, dcId, podId, clusterId, uri, username, password, hostTags);
            try {
                resources = discoverer.find(dcId, podId, clusterId, uri, username, password, hostTags);
            } catch (final DiscoveryException e) {
                throw e;
            } catch (final Exception e) {
                s_logger.info("Exception in host discovery process with discoverer: " + discoverer.getName() + ", skip to another discoverer if there is any");
            }
            processResourceEvent(ResourceListener.EVENT_DISCOVER_AFTER, resources);

            if (resources != null) {
                for (final Map.Entry<? extends ServerResource, Map<String, String>> entry : resources.entrySet()) {
                    final ServerResource resource = entry.getKey();
          /*
           * For KVM, if we go to here, that means kvm agent is
           * already connected to mgt svr.
           */
                    if (resource instanceof KvmDummyResourceBase) {
                        final Map<String, String> details = entry.getValue();
                        final String guid = details.get("guid");
                        final List<HostVO> kvmHosts = listAllUpAndEnabledHosts(Host.Type.Routing, clusterId, podId, dcId);
                        for (final HostVO host : kvmHosts) {
                            if (host.getGuid().equalsIgnoreCase(guid)) {
                                if (hostTags != null) {
                                    if (s_logger.isTraceEnabled()) {
                                        s_logger.trace("Adding Host Tags for KVM host, tags:  :" + hostTags);
                                    }
                                    _hostTagsDao.persist(host.getId(), hostTags);
                                }
                                hosts.add(host);
                                return hosts;
                            }
                        }
                        return null;
                    }

                    final HostVO host;
                    if (deferAgentCreation) {
                        host = (HostVO) createHostAndAgentDeferred(resource, entry.getValue(), true, hostTags, false);
                    } else {
                        host = (HostVO) createHostAndAgent(resource, entry.getValue(), true, hostTags, false);
                    }
                    if (host != null) {
                        hosts.add(host);
                    }
                    discoverer.postDiscovery(hosts, _nodeId);
                }
                s_logger.info("server resources successfully discovered by " + discoverer.getName());
                return hosts;
            }
        }
        if (!isHypervisorTypeSupported) {
            final String msg = "Do not support HypervisorType " + hypervisorType + " for " + url;
            s_logger.warn(msg);
            throw new DiscoveryException(msg);
        }
        s_logger.warn("Unable to find the server resources at " + url);
        throw new DiscoveryException("Unable to add the host");
    }

    private Long getOrCreateCluster(final DataCenterVO zone, final HostPodVO pod, Long clusterId, final String clusterName, final String hypervisorType) {
        final Long dcId = zone.getId();
        final Long podId = pod.getId();
        if (clusterName != null) {
            ClusterVO cluster = new ClusterVO(dcId, podId, clusterName);
            cluster.setHypervisorType(hypervisorType);
            try {
                cluster = _clusterDao.persist(cluster);
            } catch (final Exception e) {
                cluster = _clusterDao.findBy(clusterName, podId);
                if (cluster == null) {
                    final CloudRuntimeException ex =
                            new CloudRuntimeException("Unable to create cluster " + clusterName + " in pod with specified podId and data center with specified dcID", e);
                    ex.addProxyObject(pod.getUuid(), "podId");
                    ex.addProxyObject(zone.getUuid(), "dcId");
                    throw ex;
                }
            }
            clusterId = cluster.getId();
            if (_clusterDetailsDao.findDetail(clusterId, "cpuOvercommitRatio") == null) {
                final ClusterDetailsVO cluster_cpu_detail = new ClusterDetailsVO(clusterId, "cpuOvercommitRatio", "1");
                final ClusterDetailsVO cluster_memory_detail = new ClusterDetailsVO(clusterId, "memoryOvercommitRatio", "1");
                _clusterDetailsDao.persist(cluster_cpu_detail);
                _clusterDetailsDao.persist(cluster_memory_detail);
            }
        }
        return clusterId;
    }

    private void verifyClusterInfo(final Long podId, final Long clusterId, final String clusterName, final String hypervisorType) {
        if (clusterName != null && clusterId != null) {
            throw new InvalidParameterValueException("Can't specify cluster by both id and name");
        }

        if (hypervisorType == null || hypervisorType.isEmpty()) {
            throw new InvalidParameterValueException("Need to specify Hypervisor Type");
        }

        if ((clusterName != null || clusterId != null) && podId == null) {
            throw new InvalidParameterValueException("Can't specify cluster without specifying the pod");
        }

        if (clusterId != null) {
            if (_clusterDao.findById(clusterId) == null) {
                throw new InvalidParameterValueException("Can't find cluster by id " + clusterId);
            }
        }
    }

    @Override
    public Host updateHost(final UpdateHostCmd cmd) throws NoTransitionException {
        final Long hostId = cmd.getId();
        final Long guestOSCategoryId = cmd.getOsCategoryId();

        // Verify that the host exists
        final HostVO host = _hostDao.findById(hostId);
        if (host == null) {
            throw new InvalidParameterValueException("Host with id " + hostId + " doesn't exist");
        }

        if (cmd.getAllocationState() != null) {
            final ResourceState.Event resourceEvent = ResourceState.Event.toEvent(cmd.getAllocationState());
            if (resourceEvent != ResourceState.Event.Enable && resourceEvent != ResourceState.Event.Disable) {
                throw new CloudRuntimeException("Invalid allocation state:" + cmd.getAllocationState() + ", only Enable/Disable are allowed");
            }

            resourceStateTransitTo(host, resourceEvent, _nodeId);
        }

        if (guestOSCategoryId != null) {
            // Verify that the guest OS Category exists
            if (!(guestOSCategoryId > 0) || _guestOSCategoryDao.findById(guestOSCategoryId) == null) {
                throw new InvalidParameterValueException("Please specify a valid guest OS category.");
            }

            final GuestOSCategoryVO guestOSCategory = _guestOSCategoryDao.findById(guestOSCategoryId);
            final DetailVO guestOSDetail = _hostDetailsDao.findDetail(hostId, "guest.os.category.id");

            if (guestOSCategory != null && !GuestOSCategoryVO.CATEGORY_NONE.equalsIgnoreCase(guestOSCategory.getName())) {
                // Create/Update an entry for guest.os.category.id
                if (guestOSDetail != null) {
                    guestOSDetail.setValue(String.valueOf(guestOSCategory.getId()));
                    _hostDetailsDao.update(guestOSDetail.getId(), guestOSDetail);
                } else {
                    final Map<String, String> detail = new HashMap<>();
                    detail.put("guest.os.category.id", String.valueOf(guestOSCategory.getId()));
                    _hostDetailsDao.persist(hostId, detail);
                }
            } else {
                // Delete any existing entry for guest.os.category.id
                if (guestOSDetail != null) {
                    _hostDetailsDao.remove(guestOSDetail.getId());
                }
            }
        }

        final List<String> hostTags = cmd.getHostTags();
        if (hostTags != null) {
            if (s_logger.isDebugEnabled()) {
                s_logger.debug("Updating Host Tags to :" + hostTags);
            }
            _hostTagsDao.persist(hostId, hostTags);
        }

        final String url = cmd.getUrl();
        if (url != null) {
            _storageMgr.updateSecondaryStorage(cmd.getId(), cmd.getUrl());
        }

        final HostVO updatedHost = _hostDao.findById(hostId);
        return updatedHost;
    }

    @Override
    public Host cancelMaintenance(final CancelMaintenanceCmd cmd) {
        final Long hostId = cmd.getId();

        // verify input parameters
        final HostVO host = _hostDao.findById(hostId);
        if (host == null || host.getRemoved() != null) {
            throw new InvalidParameterValueException("Host with id " + hostId.toString() + " doesn't exist");
        }

        processResourceEvent(ResourceListener.EVENT_CANCEL_MAINTENANCE_BEFORE, hostId);
        final boolean success = cancelMaintenance(hostId);
        processResourceEvent(ResourceListener.EVENT_CANCEL_MAINTENANCE_AFTER, hostId);
        if (!success) {
            throw new CloudRuntimeException("Internal error cancelling maintenance.");
        }
        return host;
    }

    protected void processResourceEvent(final Integer event, final Object... params) {
        final List<ResourceListener> lst = _lifeCycleListeners.get(event);
        if (lst == null || lst.size() == 0) {
            return;
        }

        String eventName;
        for (final ResourceListener l : lst) {
            if (event.equals(ResourceListener.EVENT_DISCOVER_BEFORE)) {
                l.processDiscoverEventBefore((Long) params[0], (Long) params[1], (Long) params[2], (URI) params[3], (String) params[4], (String) params[5],
                        (List<String>) params[6]);
                eventName = "EVENT_DISCOVER_BEFORE";
            } else if (event.equals(ResourceListener.EVENT_DISCOVER_AFTER)) {
                l.processDiscoverEventAfter((Map<? extends ServerResource, Map<String, String>>) params[0]);
                eventName = "EVENT_DISCOVER_AFTER";
            } else if (event.equals(ResourceListener.EVENT_DELETE_HOST_BEFORE)) {
                l.processDeleteHostEventBefore((HostVO) params[0]);
                eventName = "EVENT_DELETE_HOST_BEFORE";
            } else if (event.equals(ResourceListener.EVENT_DELETE_HOST_AFTER)) {
                l.processDeletHostEventAfter((HostVO) params[0]);
                eventName = "EVENT_DELETE_HOST_AFTER";
            } else if (event.equals(ResourceListener.EVENT_CANCEL_MAINTENANCE_BEFORE)) {
                l.processCancelMaintenaceEventBefore((Long) params[0]);
                eventName = "EVENT_CANCEL_MAINTENANCE_BEFORE";
            } else if (event.equals(ResourceListener.EVENT_CANCEL_MAINTENANCE_AFTER)) {
                l.processCancelMaintenaceEventAfter((Long) params[0]);
                eventName = "EVENT_CANCEL_MAINTENANCE_AFTER";
            } else if (event.equals(ResourceListener.EVENT_PREPARE_MAINTENANCE_BEFORE)) {
                l.processPrepareMaintenaceEventBefore((Long) params[0]);
                eventName = "EVENT_PREPARE_MAINTENANCE_BEFORE";
            } else if (event.equals(ResourceListener.EVENT_PREPARE_MAINTENANCE_AFTER)) {
                l.processPrepareMaintenaceEventAfter((Long) params[0]);
                eventName = "EVENT_PREPARE_MAINTENANCE_AFTER";
            } else {
                throw new CloudRuntimeException("Unknown resource event:" + event);
            }
            s_logger.debug("Sent resource event " + eventName + " to listener " + l.getClass().getSimpleName());
        }
    }

    private boolean cancelMaintenance(final long hostId) {
        try {
            final Boolean result = propagateResourceEvent(hostId, ResourceState.Event.AdminCancelMaintenance);

            if (result != null) {
                return result;
            }
        } catch (final AgentUnavailableException e) {
            return false;
        }

        return doCancelMaintenance(hostId);
    }

    @Override
    public Host reconnectHost(final ReconnectHostCmd cmd) {
        final Long hostId = cmd.getId();

        final HostVO host = _hostDao.findById(hostId);
        if (host == null) {
            throw new InvalidParameterValueException("Host with id " + hostId.toString() + " doesn't exist");
        }

        return _agentMgr.reconnect(hostId) ? host : null;
    }

    @DB
    @Override
    public List<? extends Cluster> discoverCluster(final AddClusterCmd cmd) throws IllegalArgumentException, DiscoveryException, ResourceInUseException {
        final ResourceChecker resourceChecker = ResourceChecker.builder()
                                                               .dataCenterDao(_dcDao)
                                                               .accountManager(_accountMgr)
                                                               .hostPodDao(_podDao)
                                                               .build();
        final long dcId = cmd.getZoneId();
        final long podId = cmd.getPodId();
        final String clusterName = cmd.getClusterName();
        String url = cmd.getUrl();
        final String username = cmd.getUsername();
        final String password = cmd.getPassword();

        if (url != null) {
            url = URLDecoder.decode(url);
        }

        final URI uri;

        final DataCenterVO zone = resourceChecker.checkIfDataCenterExists(dcId);
        final Account account = CallContext.current().getCallingAccount();
        resourceChecker.checkIfDataCenterIsUsable(zone, account);

        final HostPodVO pod = _podDao.findById(podId);
        if (pod == null) {
            throw new InvalidParameterValueException("Can't find pod with specified podId " + podId);
        }

        // Check if the pod exists in the system
        if (_podDao.findById(podId) == null) {
            throw new InvalidParameterValueException("Can't find pod by id " + podId);
        }
        // check if pod belongs to the zone
        if (!Long.valueOf(pod.getDataCenterId()).equals(dcId)) {
            final InvalidParameterValueException ex = new InvalidParameterValueException("Pod with specified id doesn't belong to the zone " + dcId);
            ex.addProxyObject(pod.getUuid(), "podId");
            ex.addProxyObject(zone.getUuid(), "dcId");
            throw ex;
        }

        // Verify cluster information and create a new cluster if needed
        if (clusterName == null || clusterName.isEmpty()) {
            throw new InvalidParameterValueException("Please specify cluster name");
        }

        if (cmd.getHypervisor() == null || cmd.getHypervisor().isEmpty()) {
            throw new InvalidParameterValueException("Please specify a hypervisor");
        }

        final Hypervisor.HypervisorType hypervisorType = Hypervisor.HypervisorType.getType(cmd.getHypervisor());
        if (hypervisorType == null) {
            s_logger.error("Unable to resolve " + cmd.getHypervisor() + " to a valid supported hypervisor type");
            throw new InvalidParameterValueException("Unable to resolve " + cmd.getHypervisor() + " to a supported ");
        }

        if (zone.isSecurityGroupEnabled() && zone.getNetworkType().equals(NetworkType.Advanced)) {
            if (hypervisorType != HypervisorType.KVM && hypervisorType != HypervisorType.XenServer) {
                throw new InvalidParameterValueException("Don't support hypervisor type " + hypervisorType + " in advanced security enabled zone");
            }
        }

        Cluster.ClusterType clusterType = null;
        if (cmd.getClusterType() != null && !cmd.getClusterType().isEmpty()) {
            clusterType = Cluster.ClusterType.valueOf(cmd.getClusterType());
        }
        if (clusterType == null) {
            clusterType = Cluster.ClusterType.CloudManaged;
        }

        Grouping.AllocationState allocationState = null;
        if (cmd.getAllocationState() != null && !cmd.getAllocationState().isEmpty()) {
            try {
                allocationState = Grouping.AllocationState.valueOf(cmd.getAllocationState());
            } catch (final IllegalArgumentException ex) {
                throw new InvalidParameterValueException("Unable to resolve Allocation State '" + cmd.getAllocationState() + "' to a supported state");
            }
        }
        if (allocationState == null) {
            allocationState = Grouping.AllocationState.Enabled;
        }

        final Discoverer discoverer = getMatchingDiscover(hypervisorType);
        if (discoverer == null) {

            throw new InvalidParameterValueException("Could not find corresponding resource manager for " + cmd.getHypervisor());
        }

        final List<ClusterVO> result = new ArrayList<>();

        ClusterVO cluster = new ClusterVO(dcId, podId, clusterName);
        cluster.setHypervisorType(hypervisorType.toString());

        cluster.setClusterType(clusterType);
        cluster.setAllocationState(allocationState);
        try {
            cluster = _clusterDao.persist(cluster);
        } catch (final Exception e) {
            // no longer tolerate exception during the cluster creation phase
            final CloudRuntimeException ex = new CloudRuntimeException("Unable to create cluster " + clusterName + " in pod and data center with specified ids", e);
            // Get the pod VO object's table name.
            ex.addProxyObject(pod.getUuid(), "podId");
            ex.addProxyObject(zone.getUuid(), "dcId");
            throw ex;
        }
        result.add(cluster);

        if (clusterType == Cluster.ClusterType.CloudManaged) {
            final Map<String, String> details = new HashMap<>();
            details.put("cpuOvercommitRatio", CapacityManager.CpuOverprovisioningFactor.value().toString());
            details.put("memoryOvercommitRatio", CapacityManager.MemOverprovisioningFactor.value().toString());
            _clusterDetailsDao.persist(cluster.getId(), details);
            return result;
        }

        // save cluster details for later cluster/host cross-checking
        final Map<String, String> details = new HashMap<>();
        details.put("url", url);
        details.put("username", username);
        details.put("password", password);
        details.put("cpuOvercommitRatio", CapacityManager.CpuOverprovisioningFactor.value().toString());
        details.put("memoryOvercommitRatio", CapacityManager.MemOverprovisioningFactor.value().toString());
        _clusterDetailsDao.persist(cluster.getId(), details);

        boolean success = false;
        try {
            try {
                uri = new URI(UriUtils.encodeURIComponent(url));
                if (uri.getScheme() == null) {
                    throw new InvalidParameterValueException("uri.scheme is null " + url + ", add http:// as a prefix");
                } else if (uri.getScheme().equalsIgnoreCase("http")) {
                    if (uri.getHost() == null || uri.getHost().equalsIgnoreCase("") || uri.getPath() == null || uri.getPath().equalsIgnoreCase("")) {
                        throw new InvalidParameterValueException("Your host and/or path is wrong.  Make sure it's of the format http://hostname/path");
                    }
                }
            } catch (final URISyntaxException e) {
                throw new InvalidParameterValueException(url + " is not a valid uri");
            }

            final List<HostVO> hosts = new ArrayList<>();
            final Map<? extends ServerResource, Map<String, String>> resources;
            resources = discoverer.find(dcId, podId, cluster.getId(), uri, username, password, null);

            if (resources != null) {
                for (final Map.Entry<? extends ServerResource, Map<String, String>> entry : resources.entrySet()) {
                    final ServerResource resource = entry.getKey();

                    final HostVO host = (HostVO) createHostAndAgent(resource, entry.getValue(), true, null, false);
                    if (host != null) {
                        hosts.add(host);
                    }
                    discoverer.postDiscovery(hosts, _nodeId);
                }
                s_logger.info("External cluster has been successfully discovered by " + discoverer.getName());
                success = true;
                return result;
            }

            s_logger.warn("Unable to find the server resources at " + url);
            throw new DiscoveryException("Unable to add the external cluster");
        } finally {
            if (!success) {
                _clusterDetailsDao.deleteDetails(cluster.getId());
                _clusterDao.remove(cluster.getId());
            }
        }
    }

    @Override
    @DB
    public boolean deleteCluster(final DeleteClusterCmd cmd) {
        Transaction.execute(new TransactionCallbackNoReturn() {
            @Override
            public void doInTransactionWithoutResult(final TransactionStatus status) {
                final ClusterVO cluster = _clusterDao.lockRow(cmd.getId(), true);
                if (cluster == null) {
                    if (s_logger.isDebugEnabled()) {
                        s_logger.debug("Cluster: " + cmd.getId() + " does not even exist.  Delete call is ignored.");
                    }
                    throw new CloudRuntimeException("Cluster: " + cmd.getId() + " does not exist");
                }

                cluster.getHypervisorType();

                final List<HostVO> hosts = listAllHostsInCluster(cmd.getId());
                if (hosts.size() > 0) {
                    if (s_logger.isDebugEnabled()) {
                        s_logger.debug("Cluster: " + cmd.getId() + " still has hosts, can't remove");
                    }
                    throw new CloudRuntimeException("Cluster: " + cmd.getId() + " cannot be removed. Cluster still has hosts");
                }

                // don't allow to remove the cluster if it has non-removed storage
                // pools
                final List<StoragePoolVO> storagePools = _storagePoolDao.listPoolsByCluster(cmd.getId());
                if (storagePools.size() > 0) {
                    if (s_logger.isDebugEnabled()) {
                        s_logger.debug("Cluster: " + cmd.getId() + " still has storage pools, can't remove");
                    }
                    throw new CloudRuntimeException("Cluster: " + cmd.getId() + " cannot be removed. Cluster still has storage pools");
                }

                if (_clusterDao.remove(cmd.getId())) {
                    _capacityDao.removeBy(null, null, null, cluster.getId(), null);
                    // remove from dedicated resources
                    final DedicatedResourceVO dr = _dedicatedDao.findByClusterId(cluster.getId());
                    if (dr != null) {
                        _dedicatedDao.remove(dr.getId());
                    }
                }
            }
        });
        return true;
    }

    @Override
    @DB
    public Cluster updateCluster(final Cluster clusterToUpdate, final String clusterType, final String hypervisor, final String allocationState, final String managedstate) {

        final ClusterVO cluster = (ClusterVO) clusterToUpdate;
        // Verify cluster information and update the cluster if needed
        boolean doUpdate = false;

        if (hypervisor != null && !hypervisor.isEmpty()) {
            final Hypervisor.HypervisorType hypervisorType = Hypervisor.HypervisorType.getType(hypervisor);
            if (hypervisorType == null) {
                s_logger.error("Unable to resolve " + hypervisor + " to a valid supported hypervisor type");
                throw new InvalidParameterValueException("Unable to resolve " + hypervisor + " to a supported type");
            } else {
                cluster.setHypervisorType(hypervisor);
                doUpdate = true;
            }
        }

        final Cluster.ClusterType newClusterType;
        if (clusterType != null && !clusterType.isEmpty()) {
            try {
                newClusterType = Cluster.ClusterType.valueOf(clusterType);
            } catch (final IllegalArgumentException ex) {
                throw new InvalidParameterValueException("Unable to resolve " + clusterType + " to a supported type");
            }
            if (newClusterType == null) {
                s_logger.error("Unable to resolve " + clusterType + " to a valid supported cluster type");
                throw new InvalidParameterValueException("Unable to resolve " + clusterType + " to a supported type");
            } else {
                cluster.setClusterType(newClusterType);
                doUpdate = true;
            }
        }

        final Grouping.AllocationState newAllocationState;
        if (allocationState != null && !allocationState.isEmpty()) {
            try {
                newAllocationState = Grouping.AllocationState.valueOf(allocationState);
            } catch (final IllegalArgumentException ex) {
                throw new InvalidParameterValueException("Unable to resolve Allocation State '" + allocationState + "' to a supported state");
            }
            if (newAllocationState == null) {
                s_logger.error("Unable to resolve " + allocationState + " to a valid supported allocation State");
                throw new InvalidParameterValueException("Unable to resolve " + allocationState + " to a supported state");
            } else {
                cluster.setAllocationState(newAllocationState);
                doUpdate = true;
            }
        }

        Managed.ManagedState newManagedState = null;
        final Managed.ManagedState oldManagedState = cluster.getManagedState();
        if (managedstate != null && !managedstate.isEmpty()) {
            try {
                newManagedState = Managed.ManagedState.valueOf(managedstate);
            } catch (final IllegalArgumentException ex) {
                throw new InvalidParameterValueException("Unable to resolve Managed State '" + managedstate + "' to a supported state");
            }
            if (newManagedState == null) {
                s_logger.error("Unable to resolve Managed State '" + managedstate + "' to a supported state");
                throw new InvalidParameterValueException("Unable to resolve Managed State '" + managedstate + "' to a supported state");
            } else {
                doUpdate = true;
            }
        }

        if (doUpdate) {
            _clusterDao.update(cluster.getId(), cluster);
        }

        if (newManagedState != null && !newManagedState.equals(oldManagedState)) {
            if (newManagedState.equals(Managed.ManagedState.Unmanaged)) {
                boolean success = false;
                try {
                    cluster.setManagedState(Managed.ManagedState.PrepareUnmanaged);
                    _clusterDao.update(cluster.getId(), cluster);
                    List<HostVO> hosts = listAllUpAndEnabledHosts(Host.Type.Routing, cluster.getId(), cluster.getPodId(), cluster.getDataCenterId());
                    for (final HostVO host : hosts) {
                        if (host.getType().equals(Host.Type.Routing) && !host.getStatus().equals(Status.Down) && !host.getStatus().equals(Status.Disconnected) &&
                                !host.getStatus().equals(Status.Up) && !host.getStatus().equals(Status.Alert)) {
                            final String msg = "host " + host.getPrivateIpAddress() + " should not be in " + host.getStatus().toString() + " status";
                            throw new CloudRuntimeException("PrepareUnmanaged Failed due to " + msg);
                        }
                    }

                    for (final HostVO host : hosts) {
                        if (host.getStatus().equals(Status.Up)) {
                            umanageHost(host.getId());
                        }
                    }
                    final int retry = 40;
                    boolean lsuccess;
                    for (int i = 0; i < retry; i++) {
                        lsuccess = true;
                        try {
                            Thread.sleep(5 * 1000);
                        } catch (final Exception e) {
                        }
                        hosts = listAllUpAndEnabledHosts(Host.Type.Routing, cluster.getId(), cluster.getPodId(), cluster.getDataCenterId());
                        for (final HostVO host : hosts) {
                            if (!host.getStatus().equals(Status.Down) && !host.getStatus().equals(Status.Disconnected) && !host.getStatus().equals(Status.Alert)) {
                                lsuccess = false;
                                break;
                            }
                        }
                        if (lsuccess == true) {
                            success = true;
                            break;
                        }
                    }
                    if (success == false) {
                        throw new CloudRuntimeException("PrepareUnmanaged Failed due to some hosts are still in UP status after 5 Minutes, please try later ");
                    }
                } finally {
                    cluster.setManagedState(success ? Managed.ManagedState.Unmanaged : Managed.ManagedState.PrepareUnmanagedError);
                    _clusterDao.update(cluster.getId(), cluster);
                }
            } else if (newManagedState.equals(Managed.ManagedState.Managed)) {
                cluster.setManagedState(Managed.ManagedState.Managed);
                _clusterDao.update(cluster.getId(), cluster);
            }
        }

        return cluster;
    }

    @Override
    public List<? extends Host> discoverHosts(final AddHostCmd cmd) throws IllegalArgumentException, DiscoveryException, InvalidParameterValueException {
        Long dcId = cmd.getZoneId();
        final Long podId = cmd.getPodId();
        final Long clusterId = cmd.getClusterId();
        String clusterName = cmd.getClusterName();
        final String url = cmd.getUrl();
        final String username = cmd.getUsername();
        final String password = cmd.getPassword();
        final List<String> hostTags = cmd.getHostTags();

        dcId = _accountMgr.checkAccessAndSpecifyAuthority(CallContext.current().getCallingAccount(), dcId);

        // this is for standalone option
        if (clusterName == null && clusterId == null) {
            clusterName = "Standalone-" + url;
        }

        if (clusterId != null) {
            final ClusterVO cluster = _clusterDao.findById(clusterId);
            if (cluster == null) {
                final InvalidParameterValueException ex = new InvalidParameterValueException("can not find cluster for specified clusterId");
                ex.addProxyObject(clusterId.toString(), "clusterId");
                throw ex;
            } else {
                if (cluster.getGuid() == null) {
                    final List<HostVO> hosts = listAllHostsInCluster(clusterId);
                    if (!hosts.isEmpty()) {
                        final CloudRuntimeException ex =
                                new CloudRuntimeException("Guid is not updated for cluster with specified cluster id; need to wait for hosts in this cluster to come up");
                        ex.addProxyObject(cluster.getUuid(), "clusterId");
                        throw ex;
                    }
                }
            }
        }

        return discoverHostsFull(dcId, podId, clusterId, clusterName, url, username, password, cmd.getHypervisor(), hostTags, cmd.getFullUrlParams(), false);
    }

    @Override
    public List<? extends Host> discoverHosts(final AddSecondaryStorageCmd cmd) throws IllegalArgumentException, DiscoveryException, InvalidParameterValueException {
        final Long dcId = cmd.getZoneId();
        final String url = cmd.getUrl();
        return discoverHostsFull(dcId, null, null, null, url, null, null, "SecondaryStorage", null, null, false);
    }

    @Override
    public Host maintain(final PrepareForMaintenanceCmd cmd) {
        final Long hostId = cmd.getId();
        final HostVO host = _hostDao.findById(hostId);

        if (host == null) {
            s_logger.debug("Unable to find host " + hostId);
            throw new InvalidParameterValueException("Unable to find host with ID: " + hostId + ". Please specify a valid host ID.");
        }

        final List<VMInstanceVO> vmsRunningOnHost = _vmDao.listByHostId(hostId);

        if (!vmsRunningOnHost.isEmpty()) {
            throw new InvalidParameterValueException("There are active VMs on this host. Please migrate all VMs on this host to another host before starting maintenance.");
        }

        if (_hostDao.countBy(host.getClusterId(), ResourceState.PrepareForMaintenance, ResourceState.ErrorInMaintenance) > 0) {
            throw new InvalidParameterValueException("There are other servers in PrepareForMaintenance OR ErrorInMaintenance STATUS in cluster " + host.getClusterId());
        }

        if (_storageMgr.isLocalStorageActiveOnHost(host.getId())) {
            throw new InvalidParameterValueException("There are active VMs using the host's local storage pool. Please stop all VMs on this host that use local storage.");
        }

        try {
            processResourceEvent(ResourceListener.EVENT_PREPARE_MAINTENANCE_BEFORE, hostId);
            if (maintain(hostId)) {
                processResourceEvent(ResourceListener.EVENT_PREPARE_MAINTENANCE_AFTER, hostId);
                return _hostDao.findById(hostId);
            } else {
                throw new CloudRuntimeException("Unable to prepare for maintenance host " + hostId);
            }
        } catch (final AgentUnavailableException e) {
            throw new CloudRuntimeException("Unable to prepare for maintenance host " + hostId);
        }
    }

    @Override
    public boolean updateClusterPassword(final UpdateHostPasswordCmd command) {
        final boolean shouldUpdateHostPasswd = command.getUpdatePasswdOnHost();
        // get agents for the cluster
        final List<HostVO> hosts = listAllHostsInCluster(command.getClusterId());
        for (final HostVO host : hosts) {
            try {
        /*
         * FIXME: this is a buggy logic, check with alex. Shouldn't
         * return if propagation return non null
         */
                final Boolean result = propagateResourceEvent(host.getId(), ResourceState.Event.UpdatePassword);
                if (result != null) {
                    return result;
                }
            } catch (final AgentUnavailableException e) {
                s_logger.error("Agent is not availbale!", e);
            }

            if (shouldUpdateHostPasswd) {
                final boolean isUpdated = doUpdateHostPassword(host.getId());
                if (!isUpdated) {
                    throw new CloudRuntimeException("CloudStack failed to update the password of the Host with UUID / ID ==> " + host.getUuid() + " / " + host.getId() + ". " +
                            "Please make sure you are still able to connect to your hosts.");
                }
            }
        }

        return true;
    }

    @Override
    public boolean updateHostPassword(final UpdateHostPasswordCmd command) {
        // update agent attache password
        try {
            final Boolean result = propagateResourceEvent(command.getHostId(), ResourceState.Event.UpdatePassword);
            if (result != null) {
                return result;
            }
        } catch (final AgentUnavailableException e) {
            s_logger.error("Agent is not availbale!", e);
        }

        final boolean shouldUpdateHostPasswd = command.getUpdatePasswdOnHost();
        // If shouldUpdateHostPasswd has been set to false, the method doUpdateHostPassword() won't be called.
        return shouldUpdateHostPasswd && doUpdateHostPassword(command.getHostId());
    }

    @Override
    public Host getHost(final long hostId) {
        return _hostDao.findById(hostId);
    }

    @Override
    public Cluster getCluster(final Long clusterId) {
        return _clusterDao.findById(clusterId);
    }

    @Override
    public List<HypervisorType> getSupportedHypervisorTypes(final long zoneId, final boolean forVirtualRouter, final Long podId) {
        final List<HypervisorType> hypervisorTypes = new ArrayList<>();

        final List<ClusterVO> clustersForZone;
        if (podId != null) {
            clustersForZone = _clusterDao.listByPodId(podId);
        } else {
            clustersForZone = _clusterDao.listByZoneId(zoneId);
        }

        for (final ClusterVO cluster : clustersForZone) {
            final HypervisorType hType = cluster.getHypervisorType();
            if (!forVirtualRouter || forVirtualRouter) {
                hypervisorTypes.add(hType);
            }
        }

        return hypervisorTypes;
    }

    @Override
    @DB
    @ActionEvent(eventType = EventTypes.EVENT_HOST_RESERVATION_RELEASE, eventDescription = "releasing host reservation", async = true)
    public boolean releaseHostReservation(final Long hostId) {
        return Transaction.execute(new TransactionCallback<Boolean>() {
            @Override
            public Boolean doInTransaction(final TransactionStatus status) {
                final PlannerHostReservationVO reservationEntry = _plannerHostReserveDao.findByHostId(hostId);
                if (reservationEntry != null) {
                    final long id = reservationEntry.getId();
                    final PlannerHostReservationVO hostReservation = _plannerHostReserveDao.lockRow(id, true);
                    if (hostReservation == null) {
                        if (s_logger.isDebugEnabled()) {
                            s_logger.debug("Host reservation for host: " + hostId + " does not even exist.  Release reservartion call is ignored.");
                        }
                        return false;
                    }
                    hostReservation.setResourceUsage(null);
                    _plannerHostReserveDao.persist(hostReservation);
                    return true;
                }

                if (s_logger.isDebugEnabled()) {
                    s_logger.debug("Host reservation for host: " + hostId + " does not even exist.  Release reservartion call is ignored.");
                }

                return false;
            }
        });
    }

    @Override
    public boolean configure(final String name, final Map<String, Object> params) throws ConfigurationException {
        _defaultSystemVMHypervisor = HypervisorType.getType(_configDao.getValue(Config.SystemVMDefaultHypervisor.toString()));
        _gson = GsonHelper.getGson();

        _hypervisorsInDC = _hostDao.createSearchBuilder(String.class);
        _hypervisorsInDC.select(null, Func.DISTINCT, _hypervisorsInDC.entity().getHypervisorType());
        _hypervisorsInDC.and("hypervisorType", _hypervisorsInDC.entity().getHypervisorType(), SearchCriteria.Op.NNULL);
        _hypervisorsInDC.and("dataCenter", _hypervisorsInDC.entity().getDataCenterId(), SearchCriteria.Op.EQ);
        _hypervisorsInDC.and("id", _hypervisorsInDC.entity().getId(), SearchCriteria.Op.NEQ);
        _hypervisorsInDC.and("type", _hypervisorsInDC.entity().getType(), SearchCriteria.Op.EQ);
        _hypervisorsInDC.done();

        _gpuAvailability = _hostGpuGroupsDao.createSearchBuilder();
        _gpuAvailability.and("hostId", _gpuAvailability.entity().getHostId(), Op.EQ);
        _gpuAvailability.and("groupName", _gpuAvailability.entity().getGroupName(), Op.EQ);
        final SearchBuilder<VGPUTypesVO> join1 = _vgpuTypesDao.createSearchBuilder();
        join1.and("vgpuType", join1.entity().getVgpuType(), Op.EQ);
        join1.and("remainingCapacity", join1.entity().getRemainingCapacity(), Op.GT);
        _gpuAvailability.join("groupId", join1, _gpuAvailability.entity().getId(), join1.entity().getGpuGroupId(), JoinBuilder.JoinType.INNER);
        _gpuAvailability.done();

        return true;
    }

    @Override
    public boolean start() {
        // TODO Auto-generated method stub
        return super.start();
    }

    private boolean isFirstHostInCluster(final HostVO host) {
        boolean isFirstHost = true;
        if (host.getClusterId() != null) {
            final SearchBuilder<HostVO> sb = _hostDao.createSearchBuilder();
            sb.and("removed", sb.entity().getRemoved(), SearchCriteria.Op.NULL);
            sb.and("cluster", sb.entity().getClusterId(), SearchCriteria.Op.EQ);
            sb.done();
            final SearchCriteria<HostVO> sc = sb.create();
            sc.setParameters("cluster", host.getClusterId());

            final List<HostVO> hosts = _hostDao.search(sc, null);
            if (hosts != null && hosts.size() > 1) {
                isFirstHost = false;
            }
        }
        return isFirstHost;
    }

    private Host createHostAndAgentDeferred(final ServerResource resource, final Map<String, String> details, final boolean old, final List<String> hostTags, final boolean
            forRebalance) {
        HostVO host = null;
        StartupCommand[] cmds = null;
        boolean hostExists = false;
        boolean deferAgentCreation = true;
        boolean created = false;

        try {
            cmds = resource.initialize();
            if (cmds == null) {
                s_logger.info("Unable to fully initialize the agent because no StartupCommands are returned");
                return null;
            }

      /* Generate a random version in a dev setup situation */
            if (this.getClass().getPackage().getImplementationVersion() == null) {
                for (final StartupCommand cmd : cmds) {
                    if (cmd.getVersion() == null) {
                        cmd.setVersion(Long.toString(System.currentTimeMillis()));
                    }
                }
            }

            if (s_logger.isDebugEnabled()) {
                new Request(-1l, -1l, cmds, true, false).logD("Startup request from directly connected host: ", true);
            }

            if (old) {
                final StartupCommand firstCmd = cmds[0];
                host = findHostByGuid(firstCmd.getGuid());
                if (host == null) {
                    host = findHostByGuid(firstCmd.getGuidWithoutResource());
                }
                if (host != null && host.getRemoved() == null) { // host already
                    // added, no
                    // need to add
                    // again
                    s_logger.debug("Found the host " + host.getId() + " by guid: " + firstCmd.getGuid() + ", old host reconnected as new");
                    hostExists = true; // ensures that host status is left
                    // unchanged in case of adding same one
                    // again
                    return null;
                }
            }

            host = null;
            final GlobalLock addHostLock = GlobalLock.getInternLock("AddHostLock");
            try {
                if (addHostLock.lock(ACQUIRE_GLOBAL_LOCK_TIMEOUT_FOR_COOPERATION)) {
                    // to safely determine first host in cluster in multi-MS scenario
                    try {
                        host = createHostVO(cmds, resource, details, hostTags, ResourceStateAdapter.Event.CREATE_HOST_VO_FOR_DIRECT_CONNECT);
                        if (host != null) {
                            // if first host in cluster no need to defer agent creation
                            deferAgentCreation = !isFirstHostInCluster(host);
                        }
                    } finally {
                        addHostLock.unlock();
                    }
                }
            } finally {
                addHostLock.releaseRef();
            }

            if (host != null) {
                if (!deferAgentCreation) { // if first host in cluster then
                    created = _agentMgr.handleDirectConnectAgent(host, cmds, resource, forRebalance);
                    host = _hostDao.findById(host.getId()); // reload
                } else {
                    host = _hostDao.findById(host.getId()); // reload
                    // force host status to 'Alert' so that it is loaded for
                    // connection during next scan task
                    _agentMgr.agentStatusTransitTo(host, Status.Event.AgentDisconnected, _nodeId);

                    host = _hostDao.findById(host.getId()); // reload
                    host.setLastPinged(0); // so that scan task can pick it up
                    _hostDao.update(host.getId(), host);
                }
            }
        } catch (final Exception e) {
            s_logger.warn("Unable to connect due to ", e);
        } finally {
            if (hostExists) {
                if (cmds != null) {
                    resource.disconnected();
                }
            } else {
                if (!deferAgentCreation && !created) {
                    if (cmds != null) {
                        resource.disconnected();
                    }
                    markHostAsDisconnected(host, cmds);
                }
            }
        }

        return host;
    }
}
