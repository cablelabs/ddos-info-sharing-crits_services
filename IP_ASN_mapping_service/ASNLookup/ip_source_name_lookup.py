import re


def get_designated_source_name(as_name, isp_name):
    """
    Return the name of the primary source for this IP, and the name of the source that we should directly designate to the IP.
    :param as_name:
    :type as_name: string
    :param isp_name:
    :type isp_name: string
    :return: (string, string), a pair of the primary source name, followed by the designated source name
    """
    if not is_name_resolved(as_name):
        if is_name_resolved(isp_name):
            return isp_name
    return as_name


def get_primary_source_name(source_name):
    """
    Return the primary source that should be associated with the input source name.
    Will be the same as the source name if there is no other source to associate with input source.
    :param source_name: Name of source for which we are finding primary source name.
    :type source_name: string
    :return: string, representing primary source name
    """
    if not is_name_resolved(source_name):
        return "TBD-UNRESOLVED"
    region_specific_names_pattern = "^([A-Za-z]*)-(.*)"
    region_specific_names_result = re.search(region_specific_names_pattern, source_name)
    if region_specific_names_result:
        # Use prefix before first dash as primary source name.
        return region_specific_names_result.group(1)
    return source_name


def is_name_resolved(name):
    """
    Returns true iff we can treat the input name as having "resolved" to something meaningful.
    :param name: The name of some source.
    :type name: string
    :return: boolean
    """
    # Comments next to patterns describe the kinds of strings the pattern looks for.
    unresolved_patterns = [
        "^.$",                  # Just a single character
        "^(?!.*[A-Za-z])",      # String with no letters
        "Private$",             # Ends with "Private"
        "Reserved$",            # Ends with "Reserved"
        "^ASN",                 # Starts with "ASN"
        "^AS(?![A-Za-z])"       # Starts with "AS", followed by non-letter character
    ]
    #unresolved_names_pattern = "^.$|^(?!.*[A-Za-z])|Private$|Reserved$|^ASN|^AS(?![A-Za-z])"
    unresolved_names_pattern = '|'.join(unresolved_patterns)
    pattern_search_result = re.search(unresolved_names_pattern, name)
    if pattern_search_result:
        return False
    return True
