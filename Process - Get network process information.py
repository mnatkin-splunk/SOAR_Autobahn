"""
This playbook takes the notable identities and destination and gathers process and process information regarding the notable and places them in the "
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'check_for_host_and_process_info' block
    check_for_host_and_process_info(container=container)

    return

"""
Check for host info
"""
def check_for_host_and_process_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_for_host_and_process_info() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.dest", "!=", ""],
            ["artifact:*.cef.dest_ip", "!=", ""],
            ["artifact:*.cef.dest_nt_host", "!=", ""],
            ["artifact:*.cef.destinationHostName", "!=", ""],
            ["artifact:*.cef.src", "!=", ""],
            ["artifact:*.cef.src_ip", "!=", ""],
            ["artifact:*.cef.src_nt_host", "!=", ""],
            ["artifact:*.cef.sourceHostName", "!=", ""],
            ["artifact:*.cef.destinationAddress", "!=", ""],
            ["artifact:*.cef.sourceMacAddress", "!=", ""],
        ],
        logical_operator='or')

    # call connected blocks if condition 1 matched
    if matched:
        host_filter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    missing_data_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def missing_data_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('missing_data_comment() called')

    phantom.comment(container=container, comment="Missing user or host information to execute playbook.")

    return

def host_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('host_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.dest", "!=", ""],
            ["artifact:*.cef.dest_ip", "!=", ""],
            ["artifact:*.cef.dest_nt_host", "!=", ""],
            ["artifact:*.cef.destinationHostName", "!=", ""],
            ["artifact:*.cef.src", "!=", ""],
            ["artifact:*.cef.src_ip", "!=", ""],
            ["artifact:*.cef.src_nt_host", "!=", ""],
            ["artifact:*.cef.sourceHostName", "!=", ""],
            ["artifact:*.cef.destinationAddress", "!=", ""],
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ],
        logical_operator='or',
        name="host_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_hostnames(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def parent_process_task_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('parent_process_task_url() called')
    
    template = """/workbook_task/{0}"""

    # parameter list for template variable replacement
    parameters = [
        "parent_process_notes:custom_function:task_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="parent_process_task_url")

    parent_process_task_note(container=container)

    return

def parent_process_info_spl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('parent_process_info_spl() called')
    
    template = """%%
| tstats `summariesonly` count values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes by Processes.user Processes.parent_process_name Processes.process_name Processes.dest | `drop_dm_object_name(\"Processes\")` | search  parent_process_name= \"{0}\" |search dest = \"*{1}*\" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`  | sort -firstTime | sort by lastTime desc
%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_get_process_info:action_result.data.*.parent_process_name",
        "run_get_process_info:action_result.data.*.dest",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="parent_process_info_spl")

    run_parent_process_spl(container=container)

    return

def run_parent_process_spl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_parent_process_spl() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_parent_process_spl' call
    formatted_data_1 = phantom.get_format_data(name='parent_process_info_spl__as_list')

    parameters = []
    
    # build parameters list for 'run_parent_process_spl' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "",
            'display': "parent_process_exec,process_name,process_hash,user,dest,count,firstTime,lastTime",
            'parse_only': "",
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-es-kelby'], callback=process_info, name="run_parent_process_spl")

    return

"""
Input 0 = Task Title
Input 1 = Note Title
"""
def parent_process_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('parent_process_notes() called')
    
    input_parameter_0 = "Process analysis"
    input_parameter_1 = "Process Information:"
    formatted_data_1 = phantom.get_format_data(name='port_process_info_results')
    formatted_data_2 = phantom.get_format_data(name='process_info_results')
    formatted_data_3 = phantom.get_format_data(name='parent_process_info_results')

    parent_process_notes__note_params = None
    parent_process_notes__task_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    task_data = {}
    note_params = []
    
    # print debug statement
    #phantom.debug(formatted_data_1)
    
    if formatted_data_1 and formatted_data_2:
        
        content = formatted_data_1 + formatted_data_2 + formatted_data_3
    else:
        content = """There was a playbook failure"""
    
    for task in phantom.get_tasks(container=container):
        ## gets the current phase and  get 3rd tash(Review Indicators)
        if task['data']['name'] == input_parameter_0:
            task_data.update(task['data'])
            phantom.debug('phantom.get_tasks found the Analyze User Activity Task: task_id: {}, task_name: {}'.format(task_data['id'],task_data['name']))
        
    note_params.append({
            "note_type": "task",
            "task_id": task_data['id'],
            "container_id": container['id'],
            "title": input_parameter_1,
            "content": content,
            "phase_id": task_data['phase'],
        })
    
    parent_process_notes__note_params = note_params
    parent_process_notes__task_id = task_data['id']

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='parent_process_notes:note_params', value=json.dumps(parent_process_notes__note_params))
    phantom.save_run_data(key='parent_process_notes:task_id', value=json.dumps(parent_process_notes__task_id))
    parent_process_task_url(container=container)

    return

"""
Need to fix SPL query to eval if powershell has encoding in it
"""
def get_process_info_spl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_process_info_spl() called')
    
    template = """%%
| tstats `summariesonly` count values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes by Processes.user Processes.parent_process_name Processes.process_name Processes.dest | `drop_dm_object_name(\"Processes\")` | search  process_name= \"*{0}*\" | search dest = \"*{1}*\" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`  | eval base64 =if(process_name == \"powershell.exe\", \"check for encoding\",\"unknown\") | fields user,parent_process_name, process_name, base64 ,dest, count, firstTime, lastTime, process | sort by lastTime desc
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:host_filter:condition_1:artifact:*.cef.process_name",
        "merge_hostnames:custom_function_result.data.*.item",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="get_process_info_spl")

    run_get_process_info(container=container)

    return

def run_get_process_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_get_process_info() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_get_process_info' call
    formatted_data_1 = phantom.get_format_data(name='get_process_info_spl__as_list')

    parameters = []
    
    # build parameters list for 'run_get_process_info' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "",
            'display': "parent_process_exec,process_name,process_hash,user,dest,count,firstTime,lastTime",
            'parse_only': "",
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-es-kelby'], callback=process_info_results, name="run_get_process_info")

    return

"""
Input 0 = Task Title
Input 1 = Note Title
"""
def process_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('process_notes() called')
    
    input_parameter_0 = "Process analysis"
    input_parameter_1 = "Process information:"
    formatted_data_1 = phantom.get_format_data(name='process_info_results')

    process_notes__note_params = None
    process_notes__task_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # print debug statement
    #phantom.debug(formatted_data_1)
    
    if formatted_data_1:
        content = formatted_data_1
    else:
        content = """ There was a playbook failure"""
    
    task_data = {}
    note_params = []
    
    for task in phantom.get_tasks(container=container):
        ## gets the current phase and  get 3rd tash(Review Indicators)
        if task['data']['name'] == input_parameter_0:
            task_data.update(task['data'])
            phantom.debug('phantom.get_tasks found the Enumerate Logged-in Users Task: task_id: {}, task_name: {}'.format(task_data['id'],task_data['name']))
    
    note_params.append({
            "note_type": "task",
            "task_id": task_data['id'],
            "container_id": container['id'],
            "title": input_parameter_1,
            "content": content,
            "phase_id": task_data['phase']
        })

    process_notes__task_id = task_data['id']
    process_notes__note_params = note_params

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='process_notes:note_params', value=json.dumps(process_notes__note_params))
    phantom.save_run_data(key='process_notes:task_id', value=json.dumps(process_notes__task_id))
    process_task_url(container=container)

    return

def process_task_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('process_task_url() called')
    
    template = """/workbook_task/{0}"""

    # parameter list for template variable replacement
    parameters = [
        "process_notes:custom_function:task_id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="process_task_url")

    process_task_notes(container=container)

    return

def parent_process_info_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('parent_process_info_results() called')
    
    template = """---
### Parent Process Information and additional process calls
Message: {1}

| User | Parent Process Name | Process Name|  First Seen | Last Seen | 
| ---- | ---- | ---- | ---- | ---- | 
%%
| {2} | {3} | {4} | {5} | {6} |
%%

| SPL Query | 
| --- |
%%
| ``` {0}  ``` |
%%
---

{7}"""

    # parameter list for template variable replacement
    parameters = [
        "run_parent_process_spl:action_result.parameter.query",
        "run_parent_process_spl:action_result.message",
        "run_parent_process_spl:action_result.data.*.user",
        "run_parent_process_spl:action_result.data.*.parent_process_name",
        "run_parent_process_spl:action_result.data.*.process_name",
        "run_parent_process_spl:action_result.data.*.firstTime",
        "run_parent_process_spl:action_result.data.*.lastTime",
        "process_info:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="parent_process_info_results")

    parent_process_notes(container=container)

    return

def process_info_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('process_info_results() called')
    
    template = """### Process Information with Parent Process Name
Message: {1}

| Host | Parent Process Name | Process Name | User | Has base64 | Count | First Seen | Last Seen |  
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
%%
| {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} |
%%

| SPL Query | 
| --- |
%%
| ``` {0}  ``` |
%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_get_process_info:action_result.parameter.query",
        "run_get_process_info:action_result.message",
        "run_get_process_info:action_result.data.*.dest",
        "run_get_process_info:action_result.data.*.parent_process_name",
        "run_get_process_info:action_result.data.*.process_name",
        "run_get_process_info:action_result.data.*.user",
        "run_get_process_info:action_result.data.*.base64",
        "run_get_process_info:action_result.data.*.count",
        "run_get_process_info:action_result.data.*.firstTime",
        "run_get_process_info:action_result.data.*.lastTime",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="process_info_results")

    check_for_process(container=container)

    return

"""
custom code:

Removes the json.loads() from process_notes__note_params = json.loads(phantom.get_run_data(key='process_notes:note_params'))
"""
def parent_process_task_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('parent_process_task_note() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    parent_process_notes__note_params = phantom.get_run_data(key='parent_process_notes:note_params')
    # collect data for 'parent_process_task_note' call

    parameters = []
    
    # build parameters list for 'parent_process_task_note' call
    parameters.append({
        'body': parent_process_notes__note_params,
        'headers': "",
        'location': "/note/",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['phantom_rest_api'], name="parent_process_task_note")

    return

def check_for_process(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_for_process() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_get_process_info:action_result.status", "==", "success"],
            ["run_get_process_info:action_result.summary.total_events", ">", 0],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        parent_process_info_spl(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    process_notes(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def process_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('process_info() called')
    
    template = """---

### First time | Last Time | Parent Process | Process called 

----

%%
- {0} | {1} | {2} | ` {3} `

%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_parent_process_spl:action_result.data.*.firstTime",
        "run_parent_process_spl:action_result.data.*.lastTime",
        "run_parent_process_spl:action_result.data.*.parent_process_name",
        "run_parent_process_spl:action_result.data.*.process",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="process_info")

    parent_process_info_results(container=container)

    return

"""
custom code:

Removes the json.loads() from process_notes__note_params = json.loads(phantom.get_run_data(key='process_notes:note_params'))
"""
def process_task_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('process_task_notes() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    process_notes__note_params = phantom.get_run_data(key='process_notes:note_params')
    # collect data for 'process_task_notes' call

    parameters = []
    
    # build parameters list for 'process_task_notes' call
    parameters.append({
        'location': "/note/",
        'body': process_notes__note_params,
        'headers': "",
        'verify_certificate': False,
    })

    phantom.act(action="post data", parameters=parameters, assets=['phantom_rest_api'], name="process_task_notes")

    return

def get_port_process_spl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_port_process_spl() called')
    
    template = """%%
| tstats `security_content_summariesonly` count min(_time)  as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.dest = \"*{0}*\" by Processes.process_name Processes.user Processes.dest Processes.process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`|`security_content_ctime(lastTime)` | search [| tstats `security_content_summariesonly` count from datamodel=Endpoint.Ports where Ports.dest_port=\"{1}\" OR Ports.dest_port=\"53\" by Ports.process_id Ports.src  | `drop_dm_object_name(Ports)` | rename src as dest]  | sort by lastTime desc
%%"""

    # parameter list for template variable replacement
    parameters = [
        "merge_hostnames:custom_function_result.data.*.item",
        "artifact:*.cef.dest_port",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="get_port_process_spl")

    get_process_by_dest_port(container=container)

    return

def get_process_by_dest_port(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_process_by_dest_port() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_process_by_dest_port' call
    formatted_data_1 = phantom.get_format_data(name='get_port_process_spl__as_list')

    parameters = []
    
    # build parameters list for 'get_process_by_dest_port' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "",
            'display': "process_name,user,dest,process_id,count,firstTime,lastTime",
            'parse_only': "",
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk-es-kelby'], callback=port_process_info_results, name="get_process_by_dest_port")

    return

def port_process_info_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('port_process_info_results() called')
    
    template = """### Process Information from Host by Notable Destination Port and DNS port
Message: {1}

| Process Name | User | Host | Process Id | Count | First Seen | Last Seen |  
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
%%
| {2} | {3} | {4} | {5} | {6} | {7} | {8} | 
%%

| SPL Query | 
| --- |
%%
| ``` {0}  ``` |
%%"""

    # parameter list for template variable replacement
    parameters = [
        "get_process_by_dest_port:action_result.parameter.query",
        "get_process_by_dest_port:action_result.message",
        "get_process_by_dest_port:action_result.data.*.process_name",
        "get_process_by_dest_port:action_result.data.*.user",
        "get_process_by_dest_port:action_result.data.*.host",
        "get_process_by_dest_port:action_result.data.*.process_id",
        "get_process_by_dest_port:action_result.data.*.count",
        "get_process_by_dest_port:action_result.data.*.firstTime",
        "get_process_by_dest_port:action_result.data.*.lastTime",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="port_process_info_results")

    get_process_info_spl(container=container)

    return

def merge_hostnames(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('merge_hostnames() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:host_filter:condition_1:artifact:*.cef.dest', 'filtered-data:host_filter:condition_1:artifact:*.cef.dest_ip', 'filtered-data:host_filter:condition_1:artifact:*.cef.dest_nt_host', 'filtered-data:host_filter:condition_1:artifact:*.cef.destinationHostName', 'filtered-data:host_filter:condition_1:artifact:*.cef.src', 'filtered-data:host_filter:condition_1:artifact:*.cef.src_ip', 'filtered-data:host_filter:condition_1:artifact:*.cef.src_nt_host', 'filtered-data:host_filter:condition_1:artifact:*.cef.sourceHostName', 'filtered-data:host_filter:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:host_filter:condition_1:artifact:*.cef.destinationAddress'])

    parameters = []

    filtered_artifacts_data_0_0 = [item[0] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_1 = [item[1] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_2 = [item[2] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_3 = [item[3] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_4 = [item[4] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_5 = [item[5] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_6 = [item[6] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_7 = [item[7] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_8 = [item[8] for item in filtered_artifacts_data_0]
    filtered_artifacts_data_0_9 = [item[9] for item in filtered_artifacts_data_0]

    parameters.append({
        'input_1': filtered_artifacts_data_0_0,
        'input_2': filtered_artifacts_data_0_1,
        'input_3': filtered_artifacts_data_0_2,
        'input_4': filtered_artifacts_data_0_3,
        'input_5': filtered_artifacts_data_0_4,
        'input_6': filtered_artifacts_data_0_5,
        'input_7': filtered_artifacts_data_0_6,
        'input_8': filtered_artifacts_data_0_7,
        'input_9': filtered_artifacts_data_0_8,
        'input_10': filtered_artifacts_data_0_9,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "enrichment/list_merge_dedup", returns the custom_function_run_id
    phantom.custom_function(custom_function='enrichment/list_merge_dedup', parameters=parameters, name='merge_hostnames', callback=get_port_process_spl)

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