package com.cloud.api.command.user.autoscale;

import com.cloud.api.APICommand;
import com.cloud.api.ApiConstants;
import com.cloud.api.BaseListCmd;
import com.cloud.api.Parameter;
import com.cloud.api.response.CounterResponse;
import com.cloud.api.response.ListResponse;
import com.cloud.network.as.Counter;
import com.cloud.user.Account;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@APICommand(name = "listCounters", description = "List the counters", responseObject = CounterResponse.class,
        requestHasSensitiveInfo = false, responseHasSensitiveInfo = false)
public class ListCountersCmd extends BaseListCmd {
    public static final Logger s_logger = LoggerFactory.getLogger(ListCountersCmd.class.getName());
    private static final String s_name = "counterresponse";

    // ///////////////////////////////////////////////////
    // ////////////// API parameters /////////////////////
    // ///////////////////////////////////////////////////

    @Parameter(name = ApiConstants.ID, type = CommandType.UUID, entityType = CounterResponse.class, description = "ID of the Counter.")
    private Long id;

    @Parameter(name = ApiConstants.NAME, type = CommandType.STRING, description = "Name of the counter.")
    private String name;

    @Parameter(name = ApiConstants.SOURCE, type = CommandType.STRING, description = "Source of the counter.")
    private String source;

    // ///////////////////////////////////////////////////
    // ///////////// API Implementation///////////////////
    // ///////////////////////////////////////////////////

    @Override
    public void execute() {
        List<? extends Counter> counters = null;
        counters = _autoScaleService.listCounters(this);
        final ListResponse<CounterResponse> response = new ListResponse<>();
        final List<CounterResponse> ctrResponses = new ArrayList<>();
        for (final Counter ctr : counters) {
            final CounterResponse ctrResponse = _responseGenerator.createCounterResponse(ctr);
            ctrResponses.add(ctrResponse);
        }

        response.setResponses(ctrResponses);
        response.setResponseName(getCommandName());
        this.setResponseObject(response);
    }

    // /////////////////////////////////////////////////
    // ///////////////// Accessors ///////////////////////
    // ///////////////////////////////////////////////////

    @Override
    public String getCommandName() {
        return s_name;
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getSource() {
        return source;
    }

    @Override
    public long getEntityOwnerId() {
        return Account.ACCOUNT_ID_SYSTEM;
    }
}
