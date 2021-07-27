"""
This playbook processes filehashes and creates a task note for every IOC review
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'check_fileHash' block
    check_fileHash(container=container)

    return

def check_fileHash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('check_fileHash() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        fileHash_filter(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    missing_data_comment(action=action, success=success, container=container, results=results, handle=handle)

    return

def fileHash_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('fileHash_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="fileHash_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        file_intelligence(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        hunt_hash(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def file_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation() called')

    # collect data for 'file_reputation' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:fileHash_filter:condition_1:artifact:*.cef.fileHash', 'filtered-data:fileHash_filter:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal'], callback=reputation_format, name="file_reputation")

    return

def file_intelligence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_intelligence() called')

    # collect data for 'file_intelligence' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:fileHash_filter:condition_1:artifact:*.cef.fileHash', 'filtered-data:fileHash_filter:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_intelligence' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("file intelligence", parameters=parameters, assets=['recorded future'], callback=intel_format, name="file_intelligence")

    return

def create_intel_tasks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('create_intel_tasks() called')
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:fileHash_filter:condition_1:artifact:*.cef.fileHash'])
    formatted_data_1 = phantom.get_format_data(name='task_title__as_list')
    formatted_data_2 = phantom.get_format_data(name='reputation_format__as_list')
    formatted_data_3 = phantom.get_format_data(name='intel_format__as_list')
    formatted_data_4 = phantom.get_format_data(name='detonate_file_format__as_list')
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    create_intel_tasks__task_params = None
    create_intel_tasks__note_params = None
    create_intel_tasks__task_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # Set and debug task default template
    task_params = []    
    note_params = []
    
    # debug input data
    #phantom.debug("Task Title:")
    #phantom.debug(formatted_data_1)
    task_title_data = formatted_data_1
        
    #phantom.debug("Reputation Note:")
    #phantom.debug(formatted_data_2)
    rep_data = formatted_data_2
    
    #phantom.debug("Whois Note:")
    #phantom.debug(formatted_data_3)
    intel_data = formatted_data_3
    
    #phantom.debug("Reputation Note:")
    #phantom.debug(formatted_data_4)
    detonate_data = formatted_data_4
    
    phantom.debug("IOCs Processed")
    #phantom.debug(filtered_artifacts_data_1)
    ioc_processed = filtered_artifacts_data_1
    
    # Organize IOCs by value with correct data for note insertion
    for ioc in ioc_processed:
        for title in task_title_data:
            if ioc[0] in title:
                ioc.append(title)
        for rep in rep_data:
            if ioc[0] in rep:
                ioc.append(rep)
        for intel in intel_data:
            if ioc[0] in intel:
                ioc.append(intel)
        for detonate in detonate_data:
            if ioc[0] in detonate:
                ioc.append(detonate)
    
    phantom.debug("Reorganzied note data to ioc.")
    #phantom.debug(ioc_processed)
    
    # Get workbook phase id
    phantom.debug('Getting current phase set')

    success, message, phase_id, phase_name = phantom.get_phase()

    phantom.debug(
        'phantom.get_phase results: success: {}, message: {}, phase_id: {}, phase_name: {}'.format(success, message, phase_id, phase_name)
    )
    
    # Create New Tasks
    create_intel_tasks__task_id = []
    
    for ioc_note in ioc_processed:
        # Create new task
        success, message, task_id = phantom.add_task(container=container, name=ioc_note[1])     
        phantom.debug('phantom.add_task results: success {}, message {}, task_id {}'.format(success, message, task_id))
        
        # Build task update parameters
        create_intel_tasks__task_id.append(task_id)
        task_params.append({
            "container_id": container['id'],
            "name": "Task: " + ioc_note[1],
            "phase_id": phase_id,
            "sla_type": "minutes",
            "sla": 15,
            "is_note_required": False,
            "description": "Review IoC Note and detailed action result data. Then run *Process IOC* playbook to add Criticality, Threat and Analyst's notes",
            "playbooks": [{"scm": "local","playbook": "Process IoC"}]
        })
        
        # Define Note content build here
        note_content = "<strong>{}</strong><br>{}{}{}".format(ioc_note[1],ioc_note[2],ioc_note[3],ioc_note[4])
        #phantom.debug("Note content: \n {}".format(note_content))
        
        # Build note parameters
        note_params.append({
            "note_type": "task",
            "task_id": task_id,
            "container_id": container['id'],
            "title": "Automated: " + ioc_note[1],
            "content": note_content,
            "phase_id": phase_id
        }) 

    # Save parameters for REST calls to update
    #phantom.debug("Debug Parameters:")
    #phantom.debug(create_intel_tasks__task_id)
    #phantom.debug(task_params)
    #phantom.debug(note_params)
    create_intel_tasks__task_params = task_params
    create_intel_tasks__note_params = note_params
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='create_intel_tasks:task_params', value=json.dumps(create_intel_tasks__task_params))
    phantom.save_run_data(key='create_intel_tasks:note_params', value=json.dumps(create_intel_tasks__note_params))
    phantom.save_run_data(key='create_intel_tasks:task_id', value=json.dumps(create_intel_tasks__task_id))
    update_task_url_format(container=container)

    return

def task_title(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('task_title() called')
    
    template = """%%
IoC Analysis of {0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:fileHash_filter:condition_1:artifact:*.cef.fileHash",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="task_title")

    create_intel_tasks(container=container)

    return

def join_task_title(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_task_title() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'file_reputation', 'hunt_hash', 'file_intelligence' ]):
        
        # call connected block "task_title"
        task_title(container=container, handle=handle)
    
    return

def update_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('update_task() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    create_intel_tasks__task_params = json.loads(phantom.get_run_data(key='create_intel_tasks:task_params'))
    # collect data for 'update_task' call
    formatted_data_1 = phantom.get_format_data(name='update_task_url_format__as_list')

    parameters = []
    
    # build parameters list for 'update_task' call
    for i, formatted_part_1 in enumerate(formatted_data_1):
        parameters.append({
            'location': formatted_part_1,
            'body': json.dumps(create_intel_tasks__task_params[i]),
            'headers': "",
            'verify_certificate': False,
        })

    phantom.act("post data", parameters=parameters, assets=['phantom rest api'], callback=create_task_notes, name="update_task")

    return

def update_task_url_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('update_task_url_format() called')
    
    template = """%%
/workbook_task/{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "create_intel_tasks:custom_function:task_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="update_task_url_format")

    update_task(container=container)

    return

def create_task_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('create_task_notes() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    create_intel_tasks__note_params = json.loads(phantom.get_run_data(key='create_intel_tasks:note_params'))
    # collect data for 'create_task_notes' call

    parameters = []
    
    # build parameters list for 'create_task_notes' call
    for note_data in create_intel_tasks__note_params:
        parameters.append({
            'location': "/note/",
            'body': json.dumps(note_data),
            'headers': "",
            'verify_certificate': False,
        })

    phantom.act("post data", parameters=parameters, assets=['phantom rest api'], name="create_task_notes", parent_action=action)

    return

def reputation_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('reputation_format() called')
    
    template = """%%
<p><strong>VirusTotal Summary of {0}:</strong> {1}, {2}<br><em>VTI link: {3}</em><br>Scan Date: {4}<br>sha1: {5}<br>sha256: {6}<br><strong>Scan Results: (Detected, Result)</strong><br>CrowdStrike: ({7}, {8})<br>Cylance: ({9}, {10})<br>ESET: ({11}, {12})<br>FireEye: ({13}, {14})<br>MalwareBytes: ({15}, {16})<br>McAfee: ({17}, {18})<br>McAfee Gateway: ({19}, {20})<br>Microsoft: ({21}, {22})<br>Symantec: ({23}, {24})<br>Sophos: ({25}, {26})</p>
%%"""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation:action_result.parameter.hash",
        "file_reputation:action_result.message",
        "file_reputation:action_result.data.*.verbose_msg",
        "file_reputation:action_result.data.*.permalink",
        "file_reputation:action_result.data.*.scan_date",
        "file_reputation:action_result.data.*.sha1",
        "file_reputation:action_result.data.*.sha256",
        "file_reputation:action_result.data.*.scans.CrowdStrike.detected",
        "file_reputation:action_result.data.*.scans.CrowdStrike.result",
        "file_reputation:action_result.data.*.scans.Cylance.detected",
        "file_reputation:action_result.data.*.scans.Cylance.result",
        "file_reputation:action_result.data.*.scans.ESET-NOD32.detected",
        "file_reputation:action_result.data.*.scans.ESET-NOD32.result",
        "file_reputation:action_result.data.*.scans.FireEye.detected",
        "file_reputation:action_result.data.*.scans.FireEye.result",
        "file_reputation:action_result.data.*.scans.Malwarebytes.detected",
        "file_reputation:action_result.data.*.scans.Malwarebytes.result",
        "file_reputation:action_result.data.*.scans.McAfee.detected",
        "file_reputation:action_result.data.*.scans.McAfee.result",
        "file_reputation:action_result.data.*.scans.McAfee-GW-Edition.detected",
        "file_reputation:action_result.data.*.scans.McAfee-GW-Edition.result",
        "file_reputation:action_result.data.*.scans.Microsoft.detected",
        "file_reputation:action_result.data.*.scans.Microsoft.result",
        "file_reputation:action_result.data.*.scans.Symantec.detected",
        "file_reputation:action_result.data.*.scans.Symantec.result",
        "file_reputation:action_result.data.*.scans.Sophos.detected",
        "file_reputation:action_result.data.*.scans.Sophos.result",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reputation_format")

    join_task_title(container=container)

    return

def intel_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('intel_format() called')
    
    template = """%%
<p><strong>Recorded Future Summary of {0}: </strong><br>{1}, Critical Label: {2}, Last seen: {3}<br><em>RF link (Intel Card): {4}</em><br>Organization: {5} , ASN: {6}<br>First Seen: {7}</p><p>1st Threat list: {20}<br>2nd Threat list: {21}</p><p><strong>1st Rule: {8}</strong> - Evidence: {9}<br><strong>2nd Rule: {10}</strong> - Evidence: {11}<br><strong>3rd Rule: {12}</strong> - Evidence: {13}<br><strong>4th Rule: {14}</strong>- Evidence: {15}<br><strong>5th Rule: {16}</strong> - Evidence: {17}<br><strong>6th Rule: {18}</strong> - Evidence: {19}</p>
%%"""

    # parameter list for template variable replacement
    parameters = [
        "file_intelligence:action_result.parameter.hash",
        "file_intelligence:action_result.data.*.risk.riskSummary",
        "file_intelligence:action_result.summary.criticalityLabel",
        "file_intelligence:action_result.summary.lastSeen",
        "file_intelligence:action_result.data.*.intelCard",
        "file_intelligence:action_result.data.*.location.organization",
        "file_intelligence:action_result.data.*.location.asn",
        "file_intelligence:action_result.data.*.timestamps.firstSeen",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.0.rule",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.0.evidenceString",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.1.rule",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.1.evidenceString",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.2.rule",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.2.evidenceString",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.3.rule",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.3.evidenceString",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.4.rule",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.4.evidenceString",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.5.rule",
        "file_intelligence:action_result.data.*.risk.evidenceDetails.5.evidenceString",
        "file_intelligence:action_result.data.*.threatLists.0.description",
        "file_intelligence:action_result.data.*.threatLists.1.description",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="intel_format")

    join_task_title(container=container)

    return

def hunt_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('hunt_hash() called')

    # collect data for 'hunt_hash' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:fileHash_filter:condition_1:artifact:*.cef.fileHash', 'filtered-data:fileHash_filter:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_hash' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("hunt hash", parameters=parameters, assets=['hybrid-analysis-personal'], callback=detonate_file_format, name="hunt_hash")

    return

def detonate_file_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('detonate_file_format() called')
    
    template = """%%
<p><strong>Falcon Sandbox Summary of {0}:</strong> {1}, {2} - {3}<br><em>Hybrid Analysis Link: https://hybrid-analysis.com/sample/{10}<br>VX family: {4}<br>Scan date: {5}<br>Name(s): {6}<br>Environment: {7}<br>Type: {8}<br>sha1: {9}<br>sha256: {10}<br>imphash: {11}<br>ssdeep: {12}</p>
%%"""

    # parameter list for template variable replacement
    parameters = [
        "hunt_hash:action_result.parameter.hash",
        "hunt_hash:action_result.message",
        "hunt_hash:action_result.data.*.verdict",
        "hunt_hash:action_result.data.*.threat_score_verbose",
        "hunt_hash:action_result.data.*.vx_family",
        "hunt_hash:action_result.data.*.analysis_start_time",
        "hunt_hash:action_result.data.*.submit_name",
        "hunt_hash:action_result.data.*.environment",
        "hunt_hash:action_result.data.*.type",
        "hunt_hash:action_result.data.*.sha1",
        "hunt_hash:action_result.data.*.sha256",
        "hunt_hash:action_result.data.*.imphash",
        "hunt_hash:action_result.data.*.ssdeep",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="detonate_file_format")

    join_task_title(container=container)

    return

def missing_data_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('missing_data_comment() called')

    phantom.comment(container=container, comment="Missing sourceAddress to execute playbook.  Check logic and playbook parameters")

    phantom.set_status(container=container, status="Open")

    phantom.set_owner(container=container, role="Administrator")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return