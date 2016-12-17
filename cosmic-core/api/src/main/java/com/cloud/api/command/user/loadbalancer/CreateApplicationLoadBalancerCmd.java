package com.cloud.api.command.user.loadbalancer;

import com.cloud.acl.RoleType;
import com.cloud.api.APICommand;
import com.cloud.api.ApiCommandJobType;
import com.cloud.api.ApiConstants;
import com.cloud.api.ApiErrorCode;
import com.cloud.api.BaseAsyncCreateCmd;
import com.cloud.api.Parameter;
import com.cloud.api.ServerApiException;
import com.cloud.api.response.ApplicationLoadBalancerResponse;
import com.cloud.api.response.NetworkResponse;
import com.cloud.context.CallContext;
import com.cloud.event.EventTypes;
import com.cloud.exception.InsufficientAddressCapacityException;
import com.cloud.exception.InsufficientVirtualNetworkCapacityException;
import com.cloud.exception.NetworkRuleConflictException;
import com.cloud.exception.ResourceAllocationException;
import com.cloud.exception.ResourceUnavailableException;
import com.cloud.network.Network;
import com.cloud.network.lb.ApplicationLoadBalancerRule;
import com.cloud.network.rules.LoadBalancerContainer.Scheme;
import com.cloud.utils.exception.InvalidParameterValueException;
import com.cloud.utils.net.NetUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@APICommand(name = "createLoadBalancer", description = "Creates a load balancer", responseObject = ApplicationLoadBalancerResponse.class, since = "4.2.0",
        requestHasSensitiveInfo = false, responseHasSensitiveInfo = false)
public class CreateApplicationLoadBalancerCmd extends BaseAsyncCreateCmd {
    public static final Logger s_logger = LoggerFactory.getLogger(CreateApplicationLoadBalancerCmd.class.getName());

    private static final String s_name = "createloadbalancerresponse";

    /////////////////////////////////////////////////////
    //////////////// API parameters /////////////////////
    /////////////////////////////////////////////////////
    @Parameter(name = ApiConstants.NAME, type = CommandType.STRING, required = true, description = "name of the load balancer")
    private String loadBalancerName;

    @Parameter(name = ApiConstants.DESCRIPTION, type = CommandType.STRING, description = "the description of the load balancer", length = 4096)
    private String description;

    @Parameter(name = ApiConstants.NETWORK_ID,
            type = CommandType.UUID,
            required = true,
            entityType = NetworkResponse.class,
            description = "The guest network the load balancer will be created for")
    private Long networkId;

    @Parameter(name = ApiConstants.SOURCE_PORT,
            type = CommandType.INTEGER,
            required = true,
            description = "the source port the network traffic will be load balanced from")
    private Integer sourcePort;

    @Parameter(name = ApiConstants.ALGORITHM, type = CommandType.STRING, required = true, description = "load balancer algorithm (source, roundrobin, leastconn)")
    private String algorithm;

    @Parameter(name = ApiConstants.INSTANCE_PORT,
            type = CommandType.INTEGER,
            required = true,
            description = "the TCP port of the virtual machine where the network traffic will be load balanced to")
    private Integer instancePort;

    @Parameter(name = ApiConstants.SOURCE_IP, type = CommandType.STRING, description = "the source IP address the network traffic will be load balanced from")
    private String sourceIp;

    @Parameter(name = ApiConstants.SOURCE_IP_NETWORK_ID,
            type = CommandType.UUID,
            entityType = NetworkResponse.class,
            required = true,
            description = "the network id of the source ip address")
    private Long sourceIpNetworkId;

    @Parameter(name = ApiConstants.SCHEME,
            type = CommandType.STRING,
            required = true,
            description = "the load balancer scheme. Supported value in this release is Internal")
    private String scheme;

    @Parameter(name = ApiConstants.FOR_DISPLAY, type = CommandType.BOOLEAN, description = "an optional field, whether to the display the rule to the end user or not", since = "4" +
            ".4", authorized = {RoleType.Admin})
    private Boolean display;

    public String getLoadBalancerName() {
        return loadBalancerName;
    }

    public Integer getPrivatePort() {
        return instancePort;
    }

    public String getProtocol() {
        return NetUtils.TCP_PROTO;
    }

    @Override
    public String getEventType() {
        return EventTypes.EVENT_LOAD_BALANCER_CREATE;
    }

    @Override
    public String getEventDescription() {
        return "creating load balancer: " + getName() + " account: " + getAccountId();
    }

    public String getName() {
        return loadBalancerName;
    }

    public long getAccountId() {
        //get account info from the network object
        final Network ntwk = _networkService.getNetwork(networkId);
        if (ntwk == null) {
            throw new InvalidParameterValueException("Invalid network ID specified");
        }

        return ntwk.getAccountId();
    }

    @Override
    public ApiCommandJobType getInstanceType() {
        return ApiCommandJobType.LoadBalancerRule;
    }

    @Override
    public void execute() throws ResourceAllocationException, ResourceUnavailableException {
        ApplicationLoadBalancerRule rule = null;
        try {
            CallContext.current().setEventDetails("Load Balancer Id: " + getEntityId());
            // State might be different after the rule is applied, so get new object here
            rule = _entityMgr.findById(ApplicationLoadBalancerRule.class, getEntityId());
            final ApplicationLoadBalancerResponse lbResponse = _responseGenerator.createLoadBalancerContainerReponse(rule, _lbService.getLbInstances(getEntityId()));
            setResponseObject(lbResponse);
            lbResponse.setResponseName(getCommandName());
        } catch (final Exception ex) {
            s_logger.warn("Failed to create load balancer due to exception ", ex);
        }

        if (rule == null) {
            throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, "Failed to create load balancer");
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
        return getAccountId();
    }

    @Override
    public void create() {
        try {

            final ApplicationLoadBalancerRule result =
                    _appLbService.createApplicationLoadBalancer(getName(), getDescription(), getScheme(), getSourceIpNetworkId(), getSourceIp(), getSourcePort(),
                            getInstancePort(), getAlgorithm(), getNetworkId(), getEntityOwnerId(), getDisplay());
            this.setEntityId(result.getId());
            this.setEntityUuid(result.getUuid());
        } catch (final NetworkRuleConflictException e) {
            s_logger.warn("Exception: ", e);
            throw new ServerApiException(ApiErrorCode.NETWORK_RULE_CONFLICT_ERROR, e.getMessage());
        } catch (final InsufficientAddressCapacityException e) {
            s_logger.warn("Exception: ", e);
            throw new ServerApiException(ApiErrorCode.INSUFFICIENT_CAPACITY_ERROR, e.getMessage());
        } catch (final InsufficientVirtualNetworkCapacityException e) {
            s_logger.warn("Exception: ", e);
            throw new ServerApiException(ApiErrorCode.INSUFFICIENT_CAPACITY_ERROR, e.getMessage());
        }
    }

    public String getDescription() {
        return description;
    }

    public Scheme getScheme() {
        if (scheme.equalsIgnoreCase(Scheme.Internal.toString())) {
            return Scheme.Internal;
        } else {
            throw new InvalidParameterValueException("Invalid value for scheme. Supported value is internal");
        }
    }

    public long getSourceIpNetworkId() {
        return sourceIpNetworkId;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public Integer getSourcePort() {
        return sourcePort.intValue();
    }

    public int getInstancePort() {
        return instancePort.intValue();
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public long getNetworkId() {
        return networkId;
    }

    /////////////////////////////////////////////////////
    /////////////////// Accessors ///////////////////////
    /////////////////////////////////////////////////////
    public Boolean getDisplay() {
        return display;
    }
}