"""
Demonstration of master and sub-playbooks. Master calls 3 specific playbooks that filters for 'URL Artifact', 'Domain Artifact' and 'IP Artifact'.

If a malicious URL is discovered the artifact is updated and HUD card pinned to show the category and other information
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
            ["artifact:*.cef.destinationAddress", "!=", ""],
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ],
        logical_operator='or',
        name="filter_Indicators:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_local_local_POV_Network_IP_Enrichment_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="filter_Indicators:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        playbook_local_local_POV_Network_Domain_Enrichment_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ],
        name="filter_Indicators:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        playbook_local_local_POV_Network_URL_Enrichment_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return

def playbook_local_local_POV_Network_Domain_Enrichment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('playbook_local_local_POV_Network_Domain_Enrichment_1() called')
    
    # call playbook "local/POV_Network_Domain_Enrichment", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/POV_Network_Domain_Enrichment", container=container)

    return

def playbook_local_local_POV_Network_IP_Enrichment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('playbook_local_local_POV_Network_IP_Enrichment_1() called')
    
    # call playbook "local/POV_Network_IP_Enrichment", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/POV_Network_IP_Enrichment", container=container)

    return

def playbook_local_local_POV_Network_URL_Enrichment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('playbook_local_local_POV_Network_URL_Enrichment_1() called')
    
    # call playbook "local/POV_Network_URL_Enrichment", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/POV_Network_URL_Enrichment", container=container)

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