import requests
from requests.auth import HTTPBasicAuth
import base64
import re
import csv
import xml.etree.ElementTree as ET
import os
import json

######################################################## ACCESS TOKEN #################################################
# OAuth2 credentials (client_id and client_secret)
client_id = 'postman'
client_secret = 'Orion123'

# User's credentials (username and password)
username = 'sas'
password = 'Orion123'

# OAuth2 endpoints
token_url = 'https://sasserver.demo.sas.com/SASLogon/oauth/token'

# Requesting OAuth2 token
token_response = requests.post(
    token_url,
    auth=HTTPBasicAuth(client_id, client_secret),
    data={
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': 'openid'
    },
    verify=False #No SSL
)
# print(token_response)
# print(token_response.json())
# Extracting the access token from the response
access_token = token_response.json().get('access_token')

# print("ACCESS TOKEN")
# print(access_token)

############################################################################################################################## 

def replace_variables(input_string, mapping, prefix):
    for old_var, new_var in mapping.items():
        if new_var:  # Check if new variable name is not blank
            new_var_with_prefix = f'{prefix}.{new_var}'
            input_string = re.sub(r'\b{}\b'.format(re.escape(old_var)), new_var_with_prefix, input_string, flags=re.IGNORECASE)
    return input_string

def read_mapping_from_csv(csv_file):
    mapping = {}
    with open(csv_file, 'r') as file:
        csv_reader = csv.reader(file)
        next(csv_reader)  # Skip header row
        for row in csv_reader:
            old_var = row[0].strip()
            new_var = row[1].strip()
            mapping[old_var] = new_var
    return mapping

################################################### READ SFM RULES FROM JSON #################################################
def read_rules_from_file():
    current_directory = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_directory, "SFM_rules.json")
    with open(file_path, 'r') as file:
        rules_data = json.load(file)
    return rules_data

############################################################################################################################## 

class Rule_SFM:
    all_rules = []

    #def __init__(self, response_string, response_header_string):
    def __init__(self, json_data):
        # Create class attributes from rule key-value pairs
        for key, value in json_data.items():
            setattr(self, key, value)

        # # Convert local variables
        self.code = self.code.replace("&rule.", "")

        # Convert %ListContains macro
        pattern = re.compile(r'%ListContains\((.*?),(.*?)\)')
        replacer = lambda match: f'(Lists.{match.group(1).strip()}.contains({match.group(2).strip()}))'
        self.code = pattern.sub(replacer, self.code)

        # convert dhms(rqo_tran_date,0,0,rqo_tran_time) to 'message.request.messageDtTm'
        pattern = re.compile(r'dhms\(\s*RQO_TRAN_DATE\s*,\s*0\s*,\s*0\s*,\s*RQO_TRAN_TIME\s*\)', re.IGNORECASE)
        self.code = re.sub(pattern, 'message.request.messageDtTm', self.code)
        pattern = re.compile(r'dhms\(\s*RQO_TRAN_DATE_ALT\s*,\s*0\s*,\s*0\s*,\s*RQO_TRAN_TIME_ALT\s*\)', re.IGNORECASE)
        self.code = re.sub(pattern, 'message.request.messageDtTm', self.code)

        # comment out %Action_Return_Result macro
        pattern = r'%Action_Return_Result\(([^,]+),([^)]+)\);'
        replacement = r'/* Action_Return_Result(\1,\2); COMMENTED ACTION_RETURN_RESULT MACRO */'
        self.code = re.sub(pattern, replacement, self.code)


        # Remove %set
        pattern = r'%set\s*\(([^)]*)\)'
        # Use re.sub to replace the matched pattern with the content inside the parentheses
        self.code = re.sub(pattern, r'\1', self.code)

        # remove characters from rule name and rule code that are not accepted by SFD
        self.name = self.name.replace('[', '').replace(']', '')
        self.name = self.name.replace("'", "")
        self.name = self.name.replace("/", "")
        self.name = self.name.replace("\\", "")
        self.code = self.code.replace('~', '')
        self.code = self.code.replace(' EQ ', ' eq ')
        self.code = self.code.replace(' NE ', ' ^= ')
        

        #Array functions
        self.code = re.sub(r'%ShiftHistoryArray\(([^)]+)\)', r'_PLACEHOLDER_SHIFTHISTORYARRAY_(\1)', self.code, flags=re.IGNORECASE)
        self.code = re.sub(r'%DeclareArray\(([^)]+)\)', r'_PLACEHOLDER_DECLAREARRAY_(\1)', self.code, flags=re.IGNORECASE)
        self.code = re.sub(r'%indexArray\(([^)]+)\)', r'_PLACEHOLDER_INDEXARRAY_(\1)', self.code, flags=re.IGNORECASE)
        self.code = re.sub(r'%get\(([^)]+)\)', r'_PLACEHOLDER_GET_(\1)', self.code, flags=re.IGNORECASE)

        #Convert %Action_ functions
        pattern = r'%Action_([^;()]+)(;|\(\);)'
        # Define the replacement string
        replacement = r'detection.\1();'
        # Use re.sub to perform the replacement
        self.code = re.sub(pattern, replacement, self.code)

        self.code = re.sub(r'%Action_(.*?)(?:\(\w*\))?', r'detection.\1', self.code)
        
        
        #Convert API and UV variables basedon mappings
        sfm_api_mappings_path = 'SFM_API_mappings.csv'
        sfm_uv_mappings_path = 'SFM_UV_mappings.csv'

        sfm_api_mappings = read_mapping_from_csv(sfm_api_mappings_path)
        self.code = replace_variables(self.code, sfm_api_mappings, 'message')

        sfm_uv_mappings = read_mapping_from_csv(sfm_uv_mappings_path)
        self.code = replace_variables(self.code, sfm_uv_mappings, 'profile')


        Rule_SFM.all_rules.append(self)


    def replace_variables_in_string(input_string, variable_mapping):
        for old_variable, new_variable in variable_mapping.items():
            input_string = input_string.replace(old_variable, new_variable)
        return input_string
    

    def create_rule_json(self,messageClassificationId, schemaName):
        json_dict = {}
        json_dict['name'] = self.name
        json_dict['description'] = self.desc
        json_dict['messageClassificationId'] = messageClassificationId
        setattr(self, "messageClassificationId", messageClassificationId)
        json_dict['schemaName'] = schemaName
        setattr(self, "schemaName", schemaName)
       
        if self.rule_type == "Variable":
            json_dict['ruleTypeName'] = 'variable'
        elif self.rule_type == "Authorization" or self.rule_type == "Queue":
            json_dict['ruleTypeName'] = 'decision'
            json_dict['alertType'] = self.alert_type
            json_dict['alertReason'] = self.alert_reason

        setattr(self, "created_rule_json", json.dumps(json_dict, indent=2))
        return self.created_rule_json
    
    def update_rule_json(self):
        json_dict = {}
        json_dict['revision'] = 0
        json_dict['name'] = self.name
        json_dict['description'] = self.desc
        json_dict['schemaName'] = self.schemaName
        
        #print(self.code)

        json_dict['code'] = base64.b64encode(self.code.encode('utf-8')).decode('utf-8')

        json_dict['operationalTimeLimit'] = 20
        
        if self.rule_type == "Variable":
            json_dict['ruleTypeName'] = 'variable'
        elif self.rule_type == "Authorization" or self.rule_type == "Queue":
            json_dict['ruleTypeName'] = 'decision'
            json_dict['alertType'] = self.alert_type
            json_dict['alertReason'] = self.alert_reason    

        setattr(self, "updated_rule_code_json", json.dumps(json_dict, indent=2))
        return self.updated_rule_code_json


############################################ SDA REST API METHODS #########################################################

def req_create_rule(self, projectID, jsondata):
    # Making an authenticated request to the API using the access token
    api_url = f"https://sasserver.demo.sas.com/detectionDefinition/projects/{projectID}/rules"
    headers = {'Authorization': f'Bearer {access_token}'}

    #convert json from str to dict
    jsondata = json.loads(jsondata)

    # print(jsondata)

    response = requests.post(api_url, headers=headers, verify=False, json=jsondata)

    # print(response)

    #Assign Etag value and ID to Rule_SFM object
    for key, value in response.headers.items():
        if key == 'Etag':
            setattr(self, 'Etag', value)

    response_dict = json.loads(response.text)

    setattr(self, 'id', response_dict['id'])

    #print(response.text)


def req_update_rule(self,projectID, jsondata, rule_id, if_match):

    #convert json from str to dict
    jsondata = json.loads(jsondata)

    # Making an authenticated request to the API using the access token
    api_url = f"https://sasserver.demo.sas.com/detectionDefinition/projects/{projectID}/rules/{rule_id}"
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/vnd.sas.detection.rule.patch+json;version=2', 'If-Match': f'{if_match}'}

    response = requests.patch(api_url, headers=headers, verify=False, json=jsondata)

    #print(response.text)

################################ IMPORT XML WITH SFM RULES AND SAVE IT IN JSON FILE #######################################################
class ImportedRule:
    def __init__(self, rule_id, base_rule_id, version, rule_type, name, code, desc, alert_reason, alert_type, components, variables):
        self.rule_id = rule_id
        self.base_rule_id = base_rule_id
        self.version = version
        self.rule_type = rule_type
        self.name = name
        self.code = code
        self.desc = desc
        self.alert_reason = alert_reason
        self.alert_type = alert_type
        self.components = components
        self.variables = variables

class Variable:
    def __init__(self, field_business_name, field_name, initial_value, field_desc, field_length, variable_type, segment_key_field_names, segment_key_field_business_names, segment_key_field_name, segment_key_field_business_name):
        self.field_business_name = field_business_name
        self.field_name = field_name
        self.initial_value = initial_value
        self.field_desc = field_desc
        self.field_length = field_length
        self.variable_type = variable_type
        self.segment_key_field_names = segment_key_field_names
        self.segment_key_field_business_names = segment_key_field_business_names
        self.segment_key_field_name = segment_key_field_name
        self.segment_key_field_business_name = segment_key_field_business_name

def parse_xml_and_export_to_json(xml_file_name):
    
    current_directory = os.path.dirname(os.path.abspath(__file__))
    xml_file_path = os.path.join(current_directory, xml_file_name)

    # Parse XML
    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    imported_rules = []

    # Iterate over all SFM rules elements
    for rule_elem in root.findall('.//Rule'):
        rule_id = rule_elem.attrib.get('ruleId')
        base_rule_id = rule_elem.attrib.get('baseRuleId')
        version = rule_elem.attrib.get('version')
        rule_type = rule_elem.attrib.get('type')

        name = rule_elem.find('./name').text
        code = rule_elem.find('./code').text
        desc = rule_elem.find('./desc').text
        alert_reason = rule_elem.find('./alertReason').text
        alert_type = rule_elem.find('./alertType').text

        components = []
        for component_elem in rule_elem.findall('.//component'):
            component = {
                'componentField': component_elem.attrib.get('componentField'),
                'componentValue': component_elem.attrib.get('componentValue')
            }
            components.append(component)

        variables = []
        variable_list_elem = rule_elem.find('./VariableList')
        if variable_list_elem is not None:
            for variable_elem in variable_list_elem.findall('.//Variable'):
                variable = Variable(
                    field_business_name=variable_elem.attrib.get('FieldBusinessName'),
                    field_name=variable_elem.attrib.get('FieldName'),
                    initial_value=variable_elem.attrib.get('InitialValue'),
                    field_desc=variable_elem.attrib.get('FieldDesc'),
                    field_length=variable_elem.attrib.get('FieldLength'),
                    variable_type=variable_elem.attrib.get('VariableType'),
                    segment_key_field_names=variable_elem.attrib.get('SegmentKeyFieldNames'),
                    segment_key_field_business_names=variable_elem.attrib.get('SegmentKeyFieldBusinessNames'),
                    segment_key_field_name=variable_elem.attrib.get('SegmentKeyFieldName'),
                    segment_key_field_business_name=variable_elem.attrib.get('SegmentKeyFieldBusinessName')
                )
                variables.append(variable)

        imported_rule = ImportedRule(rule_id, base_rule_id, version, rule_type, name, code, desc, alert_reason, alert_type, components, variables)
        imported_rules.append(imported_rule)

    # for rule in imported_rules:
    #     print("=" * 30)
    #     print(f"Rule ID: {rule.rule_id}")
    #     print(f"Base Rule ID: {rule.base_rule_id}")
    #     print(f"Version: {rule.version}")
    #     print(f"Rule Type: {rule.rule_type}")
    #     print(f"Name: {rule.name}")
    #     print(f"Code:\n{rule.code}")
    #     print("=" * 30)

    # Export SFM rules to JSON file
    output_json_file = 'SFM_rules.json'
    output_json_path = os.path.join(current_directory, output_json_file)

    # Convert ImportedRule objects to a serializable format (dictionary)
    serialized_rules = []
    for rule in imported_rules:
        serialized_rule = {
            'rule_id': rule.rule_id,
            'base_rule_id': rule.base_rule_id,
            'version': rule.version,
            'rule_type': rule.rule_type,
            'name': rule.name,
            'code': rule.code,
            'desc': rule.desc,
            'alert_reason': rule.alert_reason,
            'alert_type': rule.alert_type,
            'components': rule.components,
            'variables': [
                {
                    'field_business_name': variable.field_business_name,
                    'field_name': variable.field_name,
                    'initial_value': variable.initial_value,
                    'field_desc': variable.field_desc,
                    'field_length': variable.field_length,
                    'variable_type': variable.variable_type,
                    'segment_key_field_names': variable.segment_key_field_names,
                    'segment_key_field_business_names': variable.segment_key_field_business_names,
                    'segment_key_field_name': variable.segment_key_field_name,
                    'segment_key_field_business_name': variable.segment_key_field_business_name
                }
                for variable in rule.variables
            ]
        }
        serialized_rules.append(serialized_rule)

    # Write the serialized data to a JSON file
    with open(output_json_path, 'w') as json_file:
        json.dump(serialized_rules, json_file, indent=2)

########################################################################################################################


################################# RULES IMPORT AND Rule_SFM objects creation ###########################################

xml_file_name = 'output_digital_example.xml'
parse_xml_and_export_to_json(xml_file_name)

rules = read_rules_from_file()

for rule in rules:
    sfmrule = Rule_SFM(rule)

#Credit Cards
projectID = "464cd6e5-ae95-44e0-a681-2b80396fc2de"
messageClassificationId = "0185e2eb-d71f-4fb6-8faa-0f11bcae54e4"
schemaName = "Credit Card Fraud"

#Digital Identity
# projectID = "58f593ea-646d-4ced-932f-f113e74ce7e2"
# messageClassificationId = "ced5ac46-825b-46eb-9cc5-734a8bb58654"
# schemaName = "SFD Digital Identity"


for rule in Rule_SFM.all_rules: 
    req_create_rule(rule, projectID, rule.create_rule_json(messageClassificationId, schemaName))
    req_update_rule(rule, projectID, rule.update_rule_json(), rule.id, rule.Etag)

print("\nRules imported to SFD successfully!\n")

########################################################################################################################