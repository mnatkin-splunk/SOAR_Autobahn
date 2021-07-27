"""
This is the parent indicator processing playbook. It assigns the appropriate workbook and calls the user, computer, filehash, ip, domain and url enrichment playbooks depending on if the indicators are present.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'artifact_label_check' block
    artifact_label_check(container=container)

    return

def artifact_label_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('artifact_label_check() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.security_domain", "==", "endpoint"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_host_tag(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.security_domain", "==", "network"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        add_network_tag(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.label", "!=", ""],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        join_set_status_to_processing(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
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

def indicator_processing(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('indicator_processing() called')
    
    # call playbook "enrichment/Indicator processing", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="enrichment/Indicator processing", container=container)

    return

def join_indicator_processing(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_indicator_processing() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_indicator_processing_called'):
        return

    # no callbacks to check, call connected block "indicator_processing"
    phantom.save_run_data(key='join_indicator_processing_called', value='indicator_processing', auto=True)

    indicator_processing(container=container, handle=handle)
    
    return

def set_current_phase(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_current_phase() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['get_phase_data:action_result.data.*.parsed_response_body.data'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    set_current_phase__comment = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    comment = "Phase is currently set and will not modify."
    
    # Get current phase from container and if null set to assigned workbook phase order 1
    cdata = phantom.get_container(container['id'])
    phantom.debug('Container Current Phase Id: {} '.format(cdata['current_phase']))
    
    # Checks if current phase is null if null then assigns 1st phase in the order as current
    if cdata['current_phase'] is None:
        # Get phase data and find the 1st phase in the order to assign as current.
        for phase in results_data_1[0][0]:
            #phantom.debug("The phase: {} and order: {} has been found.".format(phase['order'],phase['name']))
            if phase['order'] == 1:
                # Set current phase from name of phase order 1
                success, message = phantom.set_phase(phase=phase['name'])
                phantom.debug('phantom.set_phase results: success: {}, message: {}'.format(success, message))
    else:
        phantom.error(comment)
        success, message = phantom.comment(comment=comment)
        phantom.debug('phantom.comment results: success: {}, message: {}'.format(success, message))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='set_current_phase:comment', value=json.dumps(set_current_phase__comment))
    join_indicator_processing(container=container)

    return

def container_phase_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('container_phase_url() called')
    
    template = """container/{0}/phases"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="container_phase_url")

    get_response_phase_data(container=container)

    return

def get_response_phase_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_response_phase_data() called')

    # collect data for 'get_response_phase_data' call
    formatted_data_1 = phantom.get_format_data(name='container_phase_url')

    parameters = []
    
    # build parameters list for 'get_response_phase_data' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act(action="get data", parameters=parameters, assets=['phantom_rest_api'], callback=check_for_phases, name="get_response_phase_data")

    return

def check_for_phases(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_for_phases() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_response_phase_data:action_result.data.*.response_body.count", "<", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        assign_workbook(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    existing_phases_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def existing_phases_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('existing_phases_comment() called')

    phantom.comment(container=container, comment="Existing phases present, playbook will not add any new phases at this time.")
    join_indicator_processing(container=container)

    return

def check_phase(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_phase() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["get_phase_data:action_result.data.*.response_body.count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        set_current_phase(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    add_phases_error(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_phases_error(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_phases_error() called')

    phantom.comment(container=container, comment="Workbook phases are not present, current phase could not be set at this time.")

    return

def get_phase_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_phase_data() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_phase_data' call
    formatted_data_1 = phantom.get_format_data(name='container_phase_url')

    parameters = []
    
    # build parameters list for 'get_phase_data' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })
    # calculate start time using delay of 0.1 minutes
    start_time = datetime.now() + timedelta(minutes=0.1)

    phantom.act(action="get data", parameters=parameters, assets=['phantom_rest_api'], callback=check_phase, start_time=start_time, name="get_phase_data")

    return

"""
Customers will need to add this new status to their configuration for use of this action.
"""
def set_status_to_processing(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_to_processing() called')

    phantom.set_status(container=container, status="New")
    container_phase_url(container=container)

    return

def join_set_status_to_processing(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_set_status_to_processing() called')

    # no callbacks to check, call connected block "set_status_to_processing"
    phantom.save_run_data(key='join_set_status_to_processing_called', value='set_status_to_processing', auto=True)

    set_status_to_processing(container=container, handle=handle)
    
    return

def add_host_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_host_tag() called')

    phantom.add_tags(container=container, tags="host")
    join_set_status_to_processing(container=container)

    return

def add_network_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_network_tag() called')

    phantom.add_tags(container=container, tags="network")
    join_set_status_to_processing(container=container)

    return

def assign_workbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('assign_workbook() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'container_id': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "enrichment/assign_workbook", returns the custom_function_run_id
    phantom.custom_function(custom_function='enrichment/assign_workbook', parameters=parameters, name='assign_workbook', callback=get_phase_data)

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