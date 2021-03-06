package com.cloud.api.command.admin.region;

import com.cloud.api.APICommand;
import com.cloud.api.ApiCommandJobType;
import com.cloud.api.ApiConstants;
import com.cloud.api.ApiErrorCode;
import com.cloud.api.BaseAsyncCreateCmd;
import com.cloud.api.Parameter;
import com.cloud.api.ServerApiException;
import com.cloud.api.response.PortableIpRangeResponse;
import com.cloud.api.response.RegionResponse;
import com.cloud.event.EventTypes;
import com.cloud.exception.ConcurrentOperationException;
import com.cloud.exception.ResourceAllocationException;
import com.cloud.region.PortableIpRange;
import com.cloud.user.Account;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@APICommand(name = "createPortableIpRange",
        responseObject = PortableIpRangeResponse.class,
        description = "adds a range of portable public IP's to a region",
        since = "4.2.0",
        requestHasSensitiveInfo = false,
        responseHasSensitiveInfo = false)
public class CreatePortableIpRangeCmd extends BaseAsyncCreateCmd {

    public static final Logger s_logger = LoggerFactory.getLogger(CreatePortableIpRangeCmd.class.getName());

    private static final String s_name = "createportableiprangeresponse";

    /////////////////////////////////////////////////////
    //////////////// API parameters /////////////////////
    /////////////////////////////////////////////////////

    @Parameter(name = ApiConstants.REGION_ID, type = CommandType.INTEGER, entityType = RegionResponse.class, required = true, description = "Id of the Region")
    private Integer regionId;

    @Parameter(name = ApiConstants.START_IP, type = CommandType.STRING, required = true, description = "the beginning IP address in the portable IP range")
    private String startIp;

    @Parameter(name = ApiConstants.END_IP, type = CommandType.STRING, required = true, description = "the ending IP address in the portable IP range")
    private String endIp;

    @Parameter(name = ApiConstants.GATEWAY, type = CommandType.STRING, required = true, description = "the gateway for the portable IP range")
    private String gateway;

    @Parameter(name = ApiConstants.NETMASK, type = CommandType.STRING, required = true, description = "the netmask of the portable IP range")
    private String netmask;

    @Parameter(name = ApiConstants.VLAN, type = CommandType.STRING, description = "VLAN id, if not specified defaulted to untagged")
    private String vlan;

    /////////////////////////////////////////////////////
    /////////////////// Accessors ///////////////////////
    /////////////////////////////////////////////////////

    public String getStartIp() {
        return startIp;
    }

    public String getEndIp() {
        return endIp;
    }

    public String getVlan() {
        return vlan;
    }

    public String getGateway() {
        return gateway;
    }

    public String getNetmask() {
        return netmask;
    }

    @Override
    public void execute() {
        final PortableIpRange portableIpRange = _entityMgr.findById(PortableIpRange.class, getEntityId());
        if (portableIpRange != null) {
            final PortableIpRangeResponse response = _responseGenerator.createPortableIPRangeResponse(portableIpRange);
            response.setResponseName(getCommandName());
            this.setResponseObject(response);
        }
    }

    /////////////////////////////////////////////////////
    /////////////// API Implementation///////////////////
    /////////////////////////////////////////////////////

    @Override
    public String getCommandName() {
        return s_name;
    }

    @Override
    public long getEntityOwnerId() {
        return Account.ACCOUNT_ID_SYSTEM;
    }

    @Override
    public void create() throws ResourceAllocationException {
        try {
            final PortableIpRange portableIpRange = _configService.createPortableIpRange(this);
            if (portableIpRange != null) {
                this.setEntityId(portableIpRange.getId());
                this.setEntityUuid(portableIpRange.getUuid());
            } else {
                throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, "Failed to create portable public IP range");
            }
        } catch (final ConcurrentOperationException ex) {
            s_logger.warn("Exception: ", ex);
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, ex.getMessage());
        }
    }

    @Override
    public String getEventType() {
        return EventTypes.EVENT_PORTABLE_IP_RANGE_CREATE;
    }

    @Override
    public String getEventDescription() {
        return "creating a portable public ip range in region: " + getRegionId();
    }

    public Integer getRegionId() {
        return regionId;
    }

    @Override
    public ApiCommandJobType getInstanceType() {
        return ApiCommandJobType.PortableIpAddress;
    }
}
