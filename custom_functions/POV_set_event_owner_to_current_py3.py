def POV_set_event_owner_to_current_py3(container=None, **kwargs):
    """
    Grabs the user running the playbook and sets the owner of the event to the current user. Passes current_owner out for downstream use.
    
    Derek King  - Splunk
    
    Args:
        container (CEF type: phantom container id): Container id
    
    Returns a JSON-serializable object that implements the configured data paths:
        currentOwner (CEF type: *): Current owner running the playbook
        userUrl (CEF type: *)
        status (CEF type: *)
        message (CEF type: *)
        username (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    status = None
    message = None
    try:
        # Get Playbook Info
        pb_info = phantom.get_playbook_info()
        # Set owner
        phantom.set_owner(container=container, user=pb_info[0]["effective_user_id"])
    except Exception as e:
        phantom.error(e)
        pass
    finally:
        currentOwner = pb_info[0]["effective_user_id"]
        status = 'success'
    
    try:
        user_url = phantom.build_phantom_rest_url("ph_user", currentOwner)
        response = phantom.requests.get(user_url, verify=False)
        r = response.json()
        username = r['username']
        phantom.debug('username = {}'.format(username))
        status = 'success'
        
    except Exception as err:
        phantom.error('Failed to get username')
        status = 'failed'
        message = err
    
    outputs = {
        'currentOwner': currentOwner,
        'userUrl': user_url,
        'username': username,
        'message': message,
        'status': status
    }
    
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
