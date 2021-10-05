"""
This is the parent indicator processing playbook. It assigns the appropriate workbook and calls the user, computer, filehash, ip, domain and url enrichment playbooks depending on if the indicators are present.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_related_events' block
    get_related_events(container=container)

    return

def artifact_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('artifact_check() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.security_domain", "==", "endpoint"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        get_process_information(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.security_domain", "==", "network"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        get_network_information(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.label", "!=", ""],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        join_set_container_attributes(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 4
    missing_event_information(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def missing_event_information(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('missing_event_information() called')

    phantom.set_status(container=container, status="Open")

    phantom.set_owner(container=container, role="Administrator")

    phantom.comment(container=container, comment="Failed to find appropriate IOCs.  Please review the Debug Logs for ingestion errors.")

    return

def indicator_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('indicator_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
            ["artifact:*.cef.fileHashMd5", "!=", ""],
            ["artifact:*.cef.fileHashSha1", "!=", ""],
            ["artifact:*.cef.fileHashSha256", "!=", ""],
            ["artifact:*.cef.fileHashSha512", "!=", ""],
        ],
        logical_operator='or',
        name="indicator_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filehash_playbook(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
            ["artifact:*.cef.src_ip", "!=", ""],
            ["artifact:*.cef.destinationAddress", "!=", ""],
            ["artifact:*.cef.dest_ip", "!=", ""],
        ],
        logical_operator='or',
        name="indicator_filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        ip_playbook(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""],
            ["artifact:*.cef.domain", "!=", ""],
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        logical_operator='or',
        name="indicator_filter:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        domain_playbook(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
            ["artifact:*.cef.url", "!=", ""],
        ],
        logical_operator='or',
        name="indicator_filter:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        url_playbook(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    # collect filtered artifact ids for 'if' condition 5
    matched_artifacts_5, matched_results_5 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationUserId", "!=", ""],
            ["artifact:*.cef.destinationUserName", "!=", ""],
            ["artifact:*.cef.duser", "!=", ""],
            ["artifact:*.cef.sourceUserId", "!=", ""],
            ["artifact:*.cef.sourceUserName", "!=", ""],
            ["artifact:*.cef.suser", "!=", ""],
            ["artifact:*.cef.destinationHostName", "!=", ""],
            ["artifact:*.cef.dhost", "!=", ""],
            ["artifact:*.cef.sourceHostName", "!=", ""],
            ["artifact:*.cef.shost", "!=", ""],
        ],
        logical_operator='or',
        name="indicator_filter:condition_5")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_5 or matched_results_5:
        host_user_analysis(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_5, filtered_results=matched_results_5)

    return

def filehash_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filehash_playbook() called')
    
    # call playbook "enrichment/Indicator Analysis - Filehash", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="enrichment/Indicator Analysis - Filehash", container=container)

    return

def ip_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_playbook() called')
    
    # call playbook "enrichment/Indicator Analysis - IP", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="enrichment/Indicator Analysis - IP", container=container)

    return

def domain_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_playbook() called')
    
    # call playbook "enrichment/Indicator Analysis - Domain", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="enrichment/Indicator Analysis - Domain", container=container)

    return

def url_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_playbook() called')
    
    # call playbook "enrichment/Indicator Analysis - URL", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="enrichment/Indicator Analysis - URL", container=container)

    return

def host_user_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('host_user_analysis() called')
    
    # call playbook "enrichment/Indicator Analysis - Host-Account", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="enrichment/Indicator Analysis - Host-Account", container=container)

    return

def set_container_attributes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_container_attributes() called')

    phantom.set_status(container=container, status="New")
    indicator_filter(container=container)

    return

def join_set_container_attributes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_set_container_attributes() called')

    # no callbacks to check, call connected block "set_container_attributes"
    phantom.save_run_data(key='join_set_container_attributes_called', value='set_container_attributes', auto=True)

    set_container_attributes(container=container, handle=handle)
    
    return

def get_process_information(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_process_information() called')
    
    # call playbook "enrichment/Get process information", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="enrichment/Get process information", container=container)
    join_set_container_attributes(container=container)

    return

def get_network_information(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_network_information() called')
    
    # call playbook "enrichment/Get network process information", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="enrichment/Get network process information", container=container)
    join_set_container_attributes(container=container)

    return

def get_related_events(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_related_events() called')
    
    # call playbook "enrichment/Get related event information", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="enrichment/Get related event information", container=container)
    artifact_check(container=container)

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