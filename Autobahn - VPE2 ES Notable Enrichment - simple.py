"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'artifact_contains_ip_address_information' block
    artifact_contains_ip_address_information(container=container)
    # call 'artifact_includes_dns_domain_information' block
    artifact_includes_dns_domain_information(container=container)

    return

def artifact_contains_ip_address_information(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_contains_ip_address_information() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""]
        ],
        name="artifact_contains_ip_address_information:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        ip_reputation_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        whois_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def artifact_includes_dns_domain_information(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_includes_dns_domain_information() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""]
        ],
        name="artifact_includes_dns_domain_information:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        domain_reputation_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'ip_reputation_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation_1", assets=["virustotal"], callback=join_set_the_event_owner)

    return


def ip_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_reputation_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'ip_reputation_2' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip reputation", parameters=parameters, name="ip_reputation_2", assets=["passivetotal"], callback=join_set_the_event_owner)

    return


def whois_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("whois_ip_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'whois_ip_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("whois ip", parameters=parameters, name="whois_ip_1", assets=["whois"], callback=join_set_the_event_owner)

    return


def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("domain_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceDnsDomain","artifact:*.id"])

    parameters = []

    # build parameters list for 'domain_reputation_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "domain": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="domain_reputation_1", assets=["virustotal"], callback=join_set_the_event_owner)

    return


def domain_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("domain_reputation_2() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.sourceDnsDomain","artifact:*.id"])

    parameters = []

    # build parameters list for 'domain_reputation_2' call
    for container_artifact_item in container_artifact_data:
        parameters.append({
            "to": container_artifact_item[0],
            "context": {'artifact_id': container_artifact_item[1]},
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("domain reputation", parameters=parameters, name="domain_reputation_2", assets=["passivetotal"], callback=join_set_the_event_owner)

    return


def join_set_the_event_owner(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_set_the_event_owner() called")

    if phantom.completed(action_names=["ip_reputation_1", "ip_reputation_2", "whois_ip_1", "domain_reputation_1", "domain_reputation_2"]):
        # call connected block "set_the_event_owner"
        set_the_event_owner(container=container, handle=handle)

    return


def set_the_event_owner(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_the_event_owner() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "container": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/POV_set_event_owner_to_current_py3", parameters=parameters, name="set_the_event_owner", callback=set_the_event_status_to_open)

    return


def set_the_event_status_to_open(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_the_event_status_to_open() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="open")

    container = phantom.get_container(container.get('id', None))

    createeventid_3(container=container)

    return


def createeventid_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("createeventid_3() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "id_value": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/CreateEventID", parameters=parameters, name="createeventid_3", callback=format_the_enrichment_information_for_analysts)

    return


def format_the_enrichment_information_for_analysts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_the_enrichment_information_for_analysts() called")

    template = """## The Phantom Event Can be found here\n{0}\n\n---\n\n## IP Reputation Summary of {1}\n\n---\n\n### VirusTotal Summary\n#### Message: {2}\n*VirusTotal link: https://www.virustotal.com/gui/ip-address/{1}*\n - Network: {3} \n - Owner: {4}\n -  ASN: {5} \n\n\n---\n\n\n### PassiveTotal Summary\n\n| Category | Context |\n|--|--|\n| SinkHole | {6} |\n| Ever Compromised | {7} |\n| Classification | {8} |\n\n\n---\n\n\n### Whois Registration \n{9}\n\n***Latest Registered:***\n- Registered Date: {10}\n- Name: {11}\n- City: {12}, State: {13}, Country: {14}\n- Description: {15}\n- Email: {16}\n- Updated: {17}\n\n---\n\n\n## Domain Reputation Summary of {18}\n\n\n---\n\n\n### VirusTotal Summary\n*VTI link: https://www.virustotal.com/gui/domain/{18}* \n\n| Category | Context |\n| --- | --- | \n| Category | {19}  | \n| Alexa domain info | {20} |\n| Alexa Rank | {21} |\n| TrendMicro category | {22} |\n| BitDefender category | {23} |\n| Forcepoint ThreatSeeker category | {24} | \n| Websense ThreatSeeker category | {25} | \n\n\n---\n\n\n### PassiveTotal Summary\n| Category | Context |\n| --- | --- | \n| SinkHole | {26} |\n| Ever Compromised | {27} |\n| Classification | {28} |\n\n\n---{1}{2}{3}{4}{5}{6}{7}{8}{9}{10{11}{12}{13}{14}{15}{16}{17}{18}{19}{20}{21}{22}{23}{24}{25}{26}{27}{28}}\n"""

    # parameter list for template variable replacement
    parameters = [
        "CreateEventUrl:custom_function:eventLink",
        "artifact:*.cef.sourceAddress",
        "vt_ip_rep:action_result.message",
        "vt_ip_rep:action_result.data.*.network",
        "vt_ip_rep:action_result.data.*.as_owner",
        "vt_ip_rep:action_result.data.*.asn",
        "pt_ip_rep:action_result.summary.sinkhole",
        "pt_ip_rep:action_result.summary.ever_compromised",
        "pt_ip_rep:action_result.summary.classification",
        "whois_ip_1:action_result.message",
        "whois_ip_1:action_result.data.*.asn_date",
        "whois_ip_1:action_result.data.*.nets.0.name",
        "whois_ip_1:action_result.data.*.nets.0.city",
        "whois_ip_1:action_result.data.*.nets.0.state",
        "whois_ip_1:action_result.data.*.nets.0.country",
        "whois_ip_1:action_result.data.*.nets.0.description",
        "whois_ip_1:action_result.data.*.nets.0.emails",
        "whois_ip_1:action_result.data.*.nets.0.updated",
        "artifact:*.cef.sourceDnsDomain",
        "vt_domain_rep:action_result.data.*.categories",
        "vt_domain_rep:action_result.data.*.Alexa domain info",
        "vt_domain_rep:action_result.data.*.Alexa rank",
        "vt_domain_rep:action_result.data.*.TrendMicro category",
        "vt_domain_rep:action_result.data.*.BitDefender category",
        "vt_domain_rep:action_result.data.*.Forcepoint ThreatSeeker category",
        "vt_domain_rep:action_result.data.*.Websense ThreatSeeker category",
        "pt_domain_rep:action_result.summary.sinkhole",
        "pt_domain_rep:action_result.summary.ever_compromised",
        "pt_domain_rep:action_result.summary.classification"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_the_enrichment_information_for_analysts")

    format_the_notable_event_id(container=container)

    return


def format_the_notable_event_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_the_notable_event_id() called")

    template = """[|makeresults | eval search=\"((rid::{0} OR orig_rid::{0}) (sid::{1} OR orig_sid::{1}))\" | table search] `notable` | table event_id\n{1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.orig_rid",
        "artifact:*.cef.orig_sid"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_the_notable_event_id")

    check_splunk_notable_event_id(container=container)

    return


def check_splunk_notable_event_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_splunk_notable_event_id() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_the_notable_event_id = phantom.get_format_data(name="format_the_notable_event_id")

    parameters = []

    if format_the_notable_event_id is not None:
        parameters.append({
            "query": format_the_notable_event_id,
            "display": "event_id",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="check_splunk_notable_event_id", assets=["splunk"], callback=decision_1)

    return


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["check_splunk_notable_event_id:action_result.data.*.event_id", "==", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        splunkeventid_notfound(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    get_status_id(action=action, success=success, container=container, results=results, handle=handle)

    return


def splunkeventid_notfound(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("splunkeventid_notfound() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Unable to Get Splunk Event ID from artifacts")

    return


def update_event_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_event_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    check_splunk_notable_event_id_result_data = phantom.collect2(container=container, datapath=["check_splunk_notable_event_id:action_result.data.*.event_id","check_splunk_notable_event_id:action_result.parameter.context.artifact_id"], action_results=results)
    get_status_id_result_data = phantom.collect2(container=container, datapath=["get_status_id:action_result.data.*.status_id","get_status_id:action_result.parameter.context.artifact_id"], action_results=results)
    format_the_enrichment_information_for_analysts = phantom.get_format_data(name="format_the_enrichment_information_for_analysts")

    parameters = []

    # build parameters list for 'update_event_1' call
    for check_splunk_notable_event_id_result_item in check_splunk_notable_event_id_result_data:
        for get_status_id_result_item in get_status_id_result_data:
            if check_splunk_notable_event_id_result_item[0] is not None:
                parameters.append({
                    "status": "in progress",
                    "comment": format_the_enrichment_information_for_analysts,
                    "event_ids": check_splunk_notable_event_id_result_item[0],
                    "integer_status": get_status_id_result_item[0],
                    "context": {'artifact_id': get_status_id_result_item[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_event_1", assets=["splunk"], callback=format_information_to_update_soar_note)

    return


def format_information_to_update_soar_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_information_to_update_soar_note() called")

    template = """{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "format_the_enrichment_information_for_analysts:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_information_to_update_soar_note")

    add_note_5(container=container)

    return


def add_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_5() called")

    format_information_to_update_soar_note = phantom.get_format_data(name="format_information_to_update_soar_note")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_information_to_update_soar_note, note_format="markdown", note_type="general", title="Enterprise Security Enrichment results")

    return


def get_status_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_status_id() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "query": "| rest /services/configs/conf-reviewstatuses | rex field=id \"^[A-Za-z0-9\\:\\/\\.\\-]+conf-reviewstatuses\\/(?<status_id>\\d{1,5})\" | search status_type=\"notable\" label=\"Reviewed by Soar\" | table status_id",
        "display": "status_id",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="get_status_id", assets=["splunk"], callback=update_event_1)

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