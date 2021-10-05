"""
Closes an event, as part of the Proof of value workbook workflow.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'add_note_1' block
    add_note_1(container=container)

    return

"""
Close Event
"""
def CloseEvent(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CloseEvent() called')

    phantom.set_status(container=container, status="Closed")

    return

def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_1() called')

    # collect data for 'add_note_1' call

    parameters = []
    
    # build parameters list for 'add_note_1' call
    parameters.append({
        'title': "POV_Close_Event",
        'content': "Event Closed by playbook",
        'phase_id': "",
        'container_id': "",
    })

    phantom.act(action="add note", parameters=parameters, assets=['phantomapp'], callback=CloseEvent, name="add_note_1")

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