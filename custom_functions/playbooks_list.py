def playbooks_list(name=None, category=None, tags=None, **kwargs):
    """
    List available Playbooks by Name, Category and Tags
    
    Args:
        name: Playbook Name
        category: Playbook Category
        tags: Comma separated list of tags
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.id: Playbook ID:
            e.g. 1234
        *.full_name: Playbook full name with repo, e.g.:
            local/playbook_name
        *.name: Playbook Name:
            e.g. My Playbook
        *.category: Playbook category:
            e.g. Uncategorized
        *.tags: List of tags:
            e.g. [ tag1, tag2, tag3 ]
        *.active: Playbook automation status:
            e.g. True or False
        *.disabled: Playbook enabled / disabled status:
            e.g. True or False
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    
    url = phantom.build_phantom_rest_url('playbook') + '?pretty&page_size=0'
    
    # Add Name
    if name:
        url += f'&_filter_name="{name}"'
    # Add Category
    if category:
        url += f'&_filter_category="{category}"'
        
    # Create list of tags and add tags minus whitespace 
    if tags:
        tags = tags.split(',')
        for tag in tags:
            url += f'&_filter_tags__icontains="{tag.strip()}"'
            
    # Fetch playbook data
    response = phantom.requests.get(uri=url, verify=False).json()
    # If playbooks were found generate output
    if response['count'] > 0:
        for data in response['data']:
            outputs.append({'id': data['id'],
                            'full_name': f"{data['_pretty_scm']}/{data['name']}",
                            'name': data['name'],
                            'category': data['category'],
                            'tags': data['tags'],
                            'active': data['active'],
                            'disabled': data['disabled']
                           })
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
