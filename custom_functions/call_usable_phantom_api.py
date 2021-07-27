def call_usable_phantom_api_py3(**kwargs):
    """
    Checks if phantom APIs are usable.
    
    Returns a JSON-serializable object that implements the configured data paths:
        status (CEF type: int)
        success (CEF type: int)
        fail (CEF type: int)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import itertools
    import traceback
    import phantom.rules as phantom
    
    outputs = {
        'status': True,
        'success': 0,
        'fail': 0,
    }
    container_name = "call_usable_phantom_api_container"
    
    # Create a container
    success, _, container_id = phantom.create_container(name=container_name, label='events')
    _, _, merge_container_id = phantom.create_container(name="call_usable_phantom_api_merge_container", label='events')
    container_dict = {
        'id': container_id
    }
    if success:
        outputs['success'] += 1
    else:
        outputs['fail'] += 1
    
    # Create Artifact
    success, _, artifact_id = phantom.add_artifact(container_dict, {"some": "raw_data"}, label="event", name="cf_artifact", severity="Medium")
    if success:
        outputs['success'] += 1
    else:
        outputs['fail'] += 1
    
    # Create Note
    success, _, note_id = phantom.add_note(container_dict, "General", title="CF_note", content="This is CF Note")
    if success:
        outputs['success'] += 1
    else:
        outputs['fail'] += 1
    
    # Create pin
    success, _, pin_id = phantom.pin(container_id, "message", "", "manual card", "grey")
    if success:
        outputs['success'] += 1
    else:
        outputs['fail'] += 1

    
       
    # Write your custom code here...
    # List here so that we can run these in order.
    
    # Feel free to remove from this list and create manual code if it's easier.
    functions_to_run = [
        {  # List of Completed Functions
            'function': phantom.address_in_network,
            'args': ['192.168.1.1', '192.168.0.1/16'],
            'kwargs': {},
        },
        {
            'function': phantom.debug,
            'args': ["Phantom Debug Is Working!"],
            'kwargs': {},
        },
        {
            'function': phantom.error,
            'args': ["Phantom Error Is Working!"],
            'kwargs': {},
        },
        {
            'function': phantom.get_base_url,
            'args': [],
            'kwargs': {},
        },
        { 
            'function': phantom.get_phantom_home,
            'args': [],
            'kwargs': {},
        },
        { 
            'function': phantom.get_rest_base_url,
            'args': [],
            'kwargs': {},
        },
        {
            'function': phantom.valid_ip,
            'args': ["192.168.1.1"],
            'kwargs': {},
        },
        {
            'function': phantom.valid_net,
            'args': ["192.168.0.1/24"],
            'kwargs': {},
        },
        # Container Commands
        {
            'function': phantom.get_container,
            'args': [container_id],
            'kwargs': {},
        },
        {
            'function': phantom.vault_info,
            'args': [],
            'kwargs': {
                'container_id': container_id
            },
        },
        {
            'function': phantom.get_notes,
            'args': [container_id],
            'kwargs': {},
        },
        { 
            'function': phantom.get_tasks,
            'args': [container_id],
            'kwargs': {},
        },
        { 
            'function': phantom.get_phase,
            'args': [container_id],
            'kwargs': {},
        },
        {
            'function': phantom.update,
            'args': [container_dict, {}],
            'kwargs': {},
        },
        {
            'function': phantom.set_sensitivity,
            'args': [{"id": container_id}, "amber"],
            'kwargs': {},
        },
        {
            'function': phantom.set_severity,
            'args': [{"id": container_id}, "low"],
            'kwargs': {},
        },
        
        # Format Calls (very barebones)
        {  # Will fail if name is supplied.
            'function': phantom.format,
            'args': [container_dict],
            'kwargs': {},
        },
        
        
        # Collect Calls (very barebones)
        {
            'function': phantom.collect,
            'args': [container_dict, "*"],
            'kwargs': {},
        },
        {
            'function': phantom.collect_from_contains,
            'args': [container_dict],
            'kwargs': {
                "contains": "data"
            },
        },
        {  # FIXME: Currently Broken
            'function': phantom.collect2,
            'args': [container_dict],
            'kwargs': {
                "datapath": ["*"],
            },
        },
        
        # Attacker IPs / Victim IPs
        
        {
            'function': phantom.attacker_ips,
            'args': [container_dict, 'all', [], []],
            'kwargs': {},
        },
        {
            'function': phantom.victim_ips,
            'args': [container_dict, 'all', [], []],
            'kwargs': {},
        },
        
        # Add List, Set List, Delete From List, Get List, Remove List, 
        
        {
            'function': phantom.set_list,
            'args': ["cf_sample_list", ["a", "b", "c"]],
            'kwargs': {},
        },
        {
            'function': phantom.add_list,
            'args': ["cf_sample_list", "d"],
            'kwargs': {},
        },
        {
            'function': phantom.delete_from_list,
            'args': ["cf_sample_list", ""],
            'kwargs': {},
        },
        {
            'function': phantom.remove_list,
            'args': ["cf_sample_list"],
            'kwargs': {},
        },
        
        # Add Tag, View Tag, Delete Tag
        
        {
            'function': phantom.add_tags,
            'args': [container_id, "cf_tag"],
            'kwargs': {},
        },
        {
            'function': phantom.get_tags,
            'args': [container_id],
            'kwargs': {},
        },
        {
            'function': phantom.remove_tags,
            'args': [container_id, "cf_tag"],
            'kwargs': {},
        },
        
        # Update Pin & Delete Pin
        
        {
            'function': phantom.update_pin,
            'args': [pin_id, "different message"],
            'kwargs': {},
        },
        {
            'function': phantom.delete_pin,
            'args': [pin_id],
            'kwargs': {},
        },    
        
        
        # Modify Container
        {
            'function': phantom.comment,
            'args': [],
            'kwargs': {
                'container': container_id,
                'comment': "This is a comment...",
            },
        },
        {
            'function': phantom.set_duetime,
            'args': [container_id],
            'kwargs': {
                'minutes': 300
            },
        },
        {
            'function': phantom.set_label,
            'args': [container_id, "events"],
            'kwargs': {},
        },
        {
            'function': phantom.set_owner,
            'args': [container_id, "admin"],
            'kwargs': {},
        },
        {
            'function': phantom.set_status,
            'args': [container_id, "New"],
            'kwargs': {},
            'verify': 'tuple_true',
        },
        
        # Parse
        {
            'function': phantom.parse_errors,
            'args': [
                [
                    {
                        'asset': None,
                        'status': 'failed',
                        'message': 'fatal error',
                    },
                ]
            ],
            'kwargs': {},
        },
        {
            'function': phantom.parse_success,
            'args': [
                [
                    {
                        'action_results': [
                            {'data': [1, 2, 3]},
                            {'data': [4, 5, 6]},
                        ]
                    },
                    {
                        'action_results': []
                    },
                    {
                        'action_results': [
                            {'data': []},
                        ]
                    },
                ]
            ],
            'kwargs': {},
        },    
        
        # Delete Artifact, Task
        {
            'function': phantom.delete_artifact,
            'args': [artifact_id],
            'kwargs': {},
        },
        
        # Promote to Case
        {
            'function': phantom.promote,
            'args': [container_id, "Suspicious Email"],
            'kwargs': {},
        },
        
        # Merge
        {
            'function': phantom.merge,
            'args': [container_id, merge_container_id],
            'kwargs': {},
        },
        
        
        # Vault Add, Remove
        {   # FIXME: Add a different file that would work here...
            'function': phantom.vault_add,
            'args': [container_id, "/var/log/yum.log", "yummy"],
            'kwargs': {},
        },
        {  # This currently silently fails due to the above silently failing as well.
            'function': phantom.vault_delete,
            'args': [],
            'kwargs': {
                "file_name": "yummy",
                "container_id": container_id,
            },
        },
            
        
        # Set Phase, Add Task
        { 
            'function': phantom.set_phase,
            'args': [container_dict, "Ingestion"],
            'kwargs': {},
        },
        { 
            'function': phantom.add_task,
            'args': [container_dict, "cf_task"],
            'kwargs': {},
        },
        
        # Close
        {
            'function': phantom.close,
            'args': [container_id],
            'kwargs': {},
        },

        # Rendering
        {
            'function': phantom.render_template,
            'args': [
                "<h1>{{title}}</h1><body>{{body}}</body>",
                {
                    'title': 'Custom Function Test',
                    'body': 'phantom.render_template',
                }
            ],
            'kwargs': {},
        },
        {  # Expect a failure that's not related to running in a custom function
            'function': phantom.get_filtered_data,
            'args': [],
            'kwargs': {
                'name': 'earl'
            },
            'verify': 'exception',
        },
        {  # Expect a failure that's not related to running in a custom function
            'function': phantom.get_format_data,
            'args': [],
            'kwargs': {
                'name': 'earl'
            },
            'verify': 'exception',
        },
        {  # Expect a failure that's not related to running in a custom function
            'function': phantom.get_run_data,
            'args': [],
            'kwargs': {
                'key': 'lock'
            },
            'verify': 'exception',
        },
        {  # Expect a failure that's not related to running in a custom function
            'function': phantom.get_action_results,
            'args': [],
            'kwargs': {
                'action_name': 'does not exist',
            },
            'verify': 'exception',
        },
        # Uncomment once PPS-23396 is resolved.    
        {  # Expect a failure that's not related to running in a custom function
            'function': phantom.get_custom_function_results,
            'args': [],
            'kwargs': {
                'custom_function_name': 'does not exist'
            },
            'verify': 'exception',
        },
    ]
        
    for function_dict in functions_to_run:

        verify = function_dict.get('verify')

        try:
            value = function_dict['function'](*function_dict['args'], **function_dict['kwargs'])
            if verify:
                if verify == "tuple_true":
                    assert value[0]
                elif verify == "tuple_false":
                    assert not value[0]
                elif verify == "true":
                    assert value
                elif verify == "false":
                    assert not value
                else:
                    raise Exception("Invalid Verify Parameter")
        except Exception as e:
            if verify == "exception" and "cannot be called from within a custom function" not in str(e):
                outputs['success'] += 1
            else:
                phantom.error("{} Raised an unexpected exception: {}".format(function_dict['function'], e))
                phantom.error(traceback.format_exc())
                outputs['fail'] += 1
        else:
            outputs['success'] += 1
    
    if outputs['fail']:
        outputs['status'] = False
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
