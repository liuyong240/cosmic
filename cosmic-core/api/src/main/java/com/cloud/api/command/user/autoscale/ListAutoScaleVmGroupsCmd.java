package com.cloud.api.command.user.autoscale;

import com.cloud.acl.RoleType;
import com.cloud.api.APICommand;
import com.cloud.api.ApiConstants;
import com.cloud.api.BaseListProjectAndAccountResourcesCmd;
import com.cloud.api.Parameter;
import com.cloud.api.response.AutoScalePolicyResponse;
import com.cloud.api.response.AutoScaleVmGroupResponse;
import com.cloud.api.response.AutoScaleVmProfileResponse;
import com.cloud.api.response.FirewallRuleResponse;
import com.cloud.api.response.ListResponse;
import com.cloud.api.response.ZoneResponse;
import com.cloud.network.as.AutoScaleVmGroup;
import com.cloud.utils.exception.InvalidParameterValueException;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@APICommand(name = "listAutoScaleVmGroups", description = "Lists autoscale vm groups.", responseObject = AutoScaleVmGroupResponse.class, entityType = {AutoScaleVmGroup.class},
        requestHasSensitiveInfo = false, responseHasSensitiveInfo = false)
public class ListAutoScaleVmGroupsCmd extends BaseListProjectAndAccountResourcesCmd {
    public static final Logger s_logger = LoggerFactory.getLogger(ListAutoScaleVmGroupsCmd.class.getName());

    private static final String s_name = "listautoscalevmgroupsresponse";

    // ///////////////////////////////////////////////////
    // ////////////// API parameters /////////////////////
    // ///////////////////////////////////////////////////

    @Parameter(name = ApiConstants.ID, type = CommandType.UUID, entityType = AutoScaleVmGroupResponse.class, description = "the ID of the autoscale vm group")
    private Long id;

    @Parameter(name = ApiConstants.LBID, type = CommandType.UUID, entityType = FirewallRuleResponse.class, description = "the ID of the loadbalancer")
    private Long loadBalancerId;

    @Parameter(name = ApiConstants.VMPROFILE_ID, type = CommandType.UUID, entityType = AutoScaleVmProfileResponse.class, description = "the ID of the profile")
    private Long profileId;

    @Parameter(name = ApiConstants.POLICY_ID, type = CommandType.UUID, entityType = AutoScalePolicyResponse.class, description = "the ID of the policy")
    private Long policyId;

    @Parameter(name = ApiConstants.ZONE_ID, type = CommandType.UUID, entityType = ZoneResponse.class, description = "the availability zone ID")
    private Long zoneId;

    @Parameter(name = ApiConstants.FOR_DISPLAY, type = CommandType.BOOLEAN, description = "list resources by display flag; only ROOT admin is eligible to pass this parameter",
            since = "4.4", authorized = {RoleType.Admin})
    private Boolean display;

    // ///////////////////////////////////////////////////
    // ///////////////// Accessors ///////////////////////
    // ///////////////////////////////////////////////////

    public Long getId() {
        return id;
    }

    public Long getLoadBalancerId() {
        return loadBalancerId;
    }

    public Long getProfileId() {
        return profileId;
    }

    public Long getPolicyId() {
        return policyId;
    }

    public Long getZoneId() {
        return zoneId;
    }

    @Override
    public Boolean getDisplay() {
        if (display != null) {
            return display;
        }
        return super.getDisplay();
    }

    // ///////////////////////////////////////////////////
    // ///////////// API Implementation///////////////////
    // ///////////////////////////////////////////////////

    @Override
    public void execute() {
        if (id != null && (loadBalancerId != null || profileId != null || policyId != null)) {
            throw new InvalidParameterValueException("When id is specified other parameters need not be specified");
        }

        final List<? extends AutoScaleVmGroup> autoScaleGroups = _autoScaleService.listAutoScaleVmGroups(this);
        final ListResponse<AutoScaleVmGroupResponse> response = new ListResponse<>();
        final List<AutoScaleVmGroupResponse> responses = new ArrayList<>();
        if (autoScaleGroups != null) {
            for (final AutoScaleVmGroup autoScaleVmGroup : autoScaleGroups) {
                final AutoScaleVmGroupResponse autoScaleVmGroupResponse = _responseGenerator.createAutoScaleVmGroupResponse(autoScaleVmGroup);
                autoScaleVmGroupResponse.setObjectName("autoscalevmgroup");
                responses.add(autoScaleVmGroupResponse);
            }
        }
        response.setResponses(responses);
        response.setResponseName(getCommandName());
        setResponseObject(response);
    }

    @Override
    public String getCommandName() {
        return s_name;
    }
}
