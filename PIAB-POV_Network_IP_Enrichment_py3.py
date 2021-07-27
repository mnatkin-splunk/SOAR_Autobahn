"""
Runs as a sub-playbook of POV_Network_Enrichment, to lookup external IP reputation and who is information, adds the data to the container it is being executed from.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_Indicators' block
    filter_Indicators(container=container)

    return

"""
Filter Artifacts that that IP Addresses (either sourceAddress or destinationAddress) fields
"""
def filter_Indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('filter_Indicators() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ],
        logical_operator='or',
        name="filter_Indicators:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        dest_in_whitelisted_ips(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        src_in_whitelisted_ips(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Processing Destination IP Addresses Format Message
"""
def ProcessIPs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ProcessIPs() called')
    
    template = """Processing Destination IP Addresses : 
%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:destinationAddressArtifacts:condition_1:artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ProcessIPs")

    ProcessDestIPsComment(container=container)

    return

"""
Add comment listing DestIPs that are being executed externally
"""
def ProcessDestIPsComment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ProcessDestIPsComment() called')

    formatted_data_1 = phantom.get_format_data(name='ProcessIPs')

    phantom.comment(container=container, comment=formatted_data_1)
    ip_reputation_1(container=container)

    return

"""
Checking artifacts with destinationAddress set. 

Do not lookup if in whitelisted_ips custom listv
"""
def dest_in_whitelisted_ips(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('dest_in_whitelisted_ips() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filter_Indicators:condition_1:artifact:*.cef.destinationAddress", "not in", "custom_list:whitelisted_ips"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        check_internal_ip_address(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Check if this is a known internal destination IP address from global config custom list
"""
def check_internal_ip_address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('check_internal_ip_address() called')
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_Indicators:condition_1:artifact:*.cef.destinationAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    check_internal_ip_address__is_internal_ip_address = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    success, message, results = phantom.get_list(list_name="globalconfig", values="internal_cidr", trace=False)
    phantom.debug('Printing success: {0}, message: {1}, results: {2}, '.format(success, message, results))
    phantom.debug('Checking for internal IPs against destinationaddress')
    
    internal_network = []
    internal_networks = results['matches'][0]['value'][1]
    phantom.debug('Internal Networks: {0} var type: {1}'.format(internal_networks,type(internal_networks)))
    internal_network = internal_networks.split(',')

    for requestIP in filtered_artifacts_item_1_0:
        for network in internal_network:
            if phantom.address_in_network(requestIP, network):
                check_internal_ip_address__is_internal_ip_address = True
            
    phantom.debug('internal_ip_address is : {}'.format(check_internal_ip_address__is_internal_ip_address))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_internal_ip_address:is_internal_ip_address', value=json.dumps(check_internal_ip_address__is_internal_ip_address))
    destinationAddressArtifacts(container=container)

    return

def is_internal_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('is_internal_ip() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["check_internal_ip_address:custom_function:is_internal_ip_address", "!=", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        ProcessIPs(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:destinationAddressArtifacts:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:destinationAddressArtifacts:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'ph': "",
                'to': "",
                'from': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['passivetotal'], callback=whois_ip_1, name="ip_reputation_1")

    return

def whois_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('whois_ip_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_ip_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:destinationAddressArtifacts:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:destinationAddressArtifacts:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_ip_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], name="whois_ip_1", parent_action=action)

    return

"""
Check if this is a known internal source IP address from global config custom list
"""
def check_Source_Internal_Address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('check_Source_Internal_Address() called')
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_Indicators:condition_1:artifact:*.cef.sourceAddress'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    check_Source_Internal_Address__is_internal_src_ip_address = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    success, message, results = phantom.get_list(list_name="globalconfig", values="internal_cidr", trace=False)
    phantom.debug('Printing success: {0}, message: {1}, results: {2}, '.format(success, message, results))
    phantom.debug('Checking for internal SourceAddresses against internal addresses')
    
    internal_network = []
    internal_networks = results['matches'][0]['value'][1]
    phantom.debug('Internal Networks: {0} var type: {1}'.format(internal_networks,type(internal_networks)))
    internal_network = internal_networks.split(',')

    for requestIP in filtered_artifacts_item_1_0:
        for network in internal_network:
            if phantom.address_in_network(requestIP, network):
                check_Source_Internal_Address__is_internal_src_ip_address = True
            
    phantom.debug('internal_ip_address is : {}'.format(check_Source_Internal_Address__is_internal_src_ip_address))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_Source_Internal_Address:is_internal_src_ip_address', value=json.dumps(check_Source_Internal_Address__is_internal_src_ip_address))
    sourceAddressArtifacts(container=container)

    return

"""
Execute actions if this is NOT an internal SrcIP Address
"""
def isinternalsrcip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('isinternalsrcip() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["check_Source_Internal_Address:custom_function:is_internal_src_ip_address", "!=", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        ProcessSrcIPsMessage(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def ip_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ip_reputation_2() called')

    # collect data for 'ip_reputation_2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_Indicators:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:filter_Indicators:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation_2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'ph': "",
                'to': "",
                'from': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['passivetotal'], callback=whois_ip_2, name="ip_reputation_2")

    return

def whois_ip_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('whois_ip_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_ip_2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:sourceAddressArtifacts:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:sourceAddressArtifacts:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_ip_2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="whois ip", parameters=parameters, assets=['whois'], name="whois_ip_2", parent_action=action)

    return

"""
Processing Source IP Addresses Format Message
"""
def ProcessSrcIPsMessage(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ProcessSrcIPsMessage() called')
    
    template = """Processing Src IP Addresses:
%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:sourceAddressArtifacts:condition_1:artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ProcessSrcIPsMessage")

    ProcessSrcIPsComment(container=container)

    return

"""
Add comment listing SrcIPs that are being executed externally
"""
def ProcessSrcIPsComment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ProcessSrcIPsComment() called')

    formatted_data_1 = phantom.get_format_data(name='ProcessSrcIPsMessage')

    phantom.comment(container=container, comment=formatted_data_1)
    ip_reputation_2(container=container)

    return

"""
Checking artifacts with sourceAddress set. 

Do not lookup if in whitelisted_ips custom list
"""
def src_in_whitelisted_ips(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('src_in_whitelisted_ips() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filter_Indicators:condition_1:artifact:*.cef.sourceAddress", "not in", "custom_list:whitelisted_ips"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        check_Source_Internal_Address(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Filter for only those artifacts with destinationAddress set
"""
def destinationAddressArtifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('destinationAddressArtifacts() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_Indicators:condition_1:artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="destinationAddressArtifacts:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        is_internal_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Filter for only those artifacts with sourceAddress set
"""
def sourceAddressArtifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('sourceAddressArtifacts() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_Indicators:condition_1:artifact:*.cef.sourceAddress", "!=", ""],
        ],
        name="sourceAddressArtifacts:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        isinternalsrcip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return