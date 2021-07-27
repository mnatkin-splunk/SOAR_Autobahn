"""
Sub-Playbook that filters artifacts for URLs, Domains, and IP Addresses. Uses whois API, URLScan.io and PassiveTotal to enrich indicators. If a malicious URL is discovered the artifact is updated and HUD card pinned to show the category and other information
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_Indicators' block
    filter_Indicators(container=container)

    return

def filter_Indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('filter_Indicators() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="filter_Indicators:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        in_top500(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def DestinationDNSDomain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('DestinationDNSDomain() called')
    
    template = """Processing Destination Domain(s)
%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_Indicators:condition_1:artifact:*.cef.destinationDnsDomain",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="DestinationDNSDomain")

    Processing_DomainName(container=container)

    return

def Processing_DomainName(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('Processing_DomainName() called')

    formatted_data_1 = phantom.get_format_data(name='DestinationDNSDomain')

    phantom.comment(container=container, comment=formatted_data_1)
    whois_domain(container=container)

    return

def in_top500(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('in_top500() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["custom_list:top500", "not in", "filtered-data:filter_Indicators:condition_1:artifact:*.cef.destinationDnsDomain"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        check_internal_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def check_internal_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('check_internal_domain() called')
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_Indicators:condition_1:artifact:*.cef.destinationDnsDomain'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    check_internal_domain__is_internal_dns_address = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    success, message, results = phantom.get_list(list_name="globalconfig", values="domains", trace=False)
    phantom.debug('Printing success: {0}, message: {1}, results: {2}, '.format(success, message, results))
    
    domains = results['matches'][0]['value'][1]
    for requestedDomain in filtered_artifacts_item_1_0:
        if requestedDomain in domains:
            check_internal_domain__is_internal_dns_address = True
            
    phantom.debug('destinationDnsAddress is : {}'.format(check_internal_domain__is_internal_dns_address))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_internal_domain:is_internal_dns_address', value=json.dumps(check_internal_domain__is_internal_dns_address))
    is_internal_domain(container=container)

    return

def is_internal_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('is_internal_domain() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["check_internal_domain:custom_function:is_internal_dns_address", "!=", True],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        DestinationDNSDomain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def passivetotal_domain_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('passivetotal_domain_reputation() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'passivetotal_domain_reputation' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_Indicators:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:filter_Indicators:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'passivetotal_domain_reputation' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ph': "",
                'to': "",
                'from': "",
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['passivetotal'], name="passivetotal_domain_reputation", parent_action=action)

    return

def whois_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('whois_domain() called')

    # collect data for 'whois_domain' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_Indicators:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:filter_Indicators:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_domain' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="whois domain", parameters=parameters, assets=['whois'], callback=passivetotal_domain_reputation, name="whois_domain")

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