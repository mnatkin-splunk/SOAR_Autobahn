"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'url_filter' block
    url_filter(container=container)

    return

def url_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("url_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "URL Artifact"]
        ],
        name="url_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        o365_decode_safelink(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def o365_decode_safelink(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("o365_decode_safelink() called")

    filtered_artifact_0_data_url_filter = phantom.collect2(container=container, datapath=["filtered-data:url_filter:condition_1:artifact:*.cef.requestURL"])

    filtered_artifact_0__cef_requesturl = [item[0] for item in filtered_artifact_0_data_url_filter]

    parameters = []

    parameters.append({
        "input_url": filtered_artifact_0__cef_requesturl,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/o365_decode_safelink", parameters=parameters, name="o365_decode_safelink", callback=whitelist_domain)

    return


def whitelist_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("whitelist_domain() called")

    o365_decode_safelink_data = phantom.collect2(container=container, datapath=["o365_decode_safelink:custom_function_result.data.*.decoded_url"])

    o365_decode_safelink_data___decoded_url = [item[0] for item in o365_decode_safelink_data]

    parameters = []

    parameters.append({
        "input": o365_decode_safelink_data___decoded_url,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/whitelist_domain", parameters=parameters, name="whitelist_domain", callback=whitelist_domain_callback)

    return


def whitelist_domain_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("whitelist_domain_callback() called")

    
    vt_detonate_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    urlscan_detonate_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    threatgrid_detonate_url(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def vt_detonate_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("vt_detonate_url() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    whitelist_domain_data = phantom.collect2(container=container, datapath=["whitelist_domain:custom_function_result.data.*.whitelisted_result"])

    parameters = []

    # build parameters list for 'vt_detonate_url' call
    for whitelist_domain_data_item in whitelist_domain_data:
        if whitelist_domain_data_item[0] is not None:
            parameters.append({
                "url": whitelist_domain_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="vt_detonate_url", assets=["virustotal"], callback=join_malicious_decision)

    return


def urlscan_detonate_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("urlscan_detonate_url() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    whitelist_domain_data = phantom.collect2(container=container, datapath=["whitelist_domain:custom_function_result.data.*.whitelisted_result"])

    parameters = []

    # build parameters list for 'urlscan_detonate_url' call
    for whitelist_domain_data_item in whitelist_domain_data:
        if whitelist_domain_data_item[0] is not None:
            parameters.append({
                "url": whitelist_domain_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="urlscan_detonate_url", assets=["urlscan.io"], callback=join_malicious_decision)

    return


def join_malicious_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("join_malicious_decision() called")

    if phantom.completed(action_names=["vt_detonate_url", "urlscan_detonate_url", "threatgrid_detonate_url"]):
        # call connected block "malicious_decision"
        malicious_decision(container=container, handle=handle)

    return


def malicious_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("malicious_decision() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["vt_detonate_url:action_result.data.*.attributes.total_votes.malicious", ">=", 1],
            ["urlscan_detonate_url:action_result.data.*.verdicts.overall.malicious", "==", True],
            ["threatgrid_detonate_url:action_result.data.*.threat.score", ">=", 50]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        prompt_analyst(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def prompt_analyst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("prompt_analyst() called")

    # set user and message variables for phantom.prompt call

    user = "jgoodrich@splunk.com"
    message = """Splunk SOAR initial phishing investigation results for event name {0}.\n\nURLs Scanned: {1}\nVirustotal Total Malicious Votes: {2}\nURLScan Malicious Verdict: {3}\nThreat Grid Score: {4}\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:name",
        "whitelist_domain:custom_function_result.data.*.whitelisted_result",
        "vt_detonate_url:action_result.data.*.attributes.total_votes.malicious",
        "urlscan_detonate_url:action_result.data.*.verdicts.overall.malicious",
        "threatgrid_detonate_url:action_result.data.*.threat.score"
    ]

    # responses
    response_types = [
        {
            "prompt": "Change event to open status? Responding no will close the event.",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1440, name="prompt_analyst", parameters=parameters, response_types=response_types, callback=decision_3)

    return


def threatgrid_detonate_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("threatgrid_detonate_url() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    whitelist_domain_data = phantom.collect2(container=container, datapath=["whitelist_domain:custom_function_result.data.*.whitelisted_result"])

    parameters = []

    # build parameters list for 'threatgrid_detonate_url' call
    for whitelist_domain_data_item in whitelist_domain_data:
        if whitelist_domain_data_item[0] is not None:
            parameters.append({
                "url": whitelist_domain_data_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate url", parameters=parameters, name="threatgrid_detonate_url", assets=["threat grid"], callback=join_malicious_decision)

    return


def set_status_open(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("set_status_open() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="open")

    container = phantom.get_container(container.get('id', None))

    return


def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_analyst:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_status_open(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    set_status_closed(action=action, success=success, container=container, results=results, handle=handle)

    return


def set_status_closed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, **kwargs):
    phantom.debug("set_status_closed() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return