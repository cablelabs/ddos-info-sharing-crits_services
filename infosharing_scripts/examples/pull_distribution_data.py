import json
import requests

credentials_file = open('credentials.json', 'r')
credentials = json.load(credentials_file)
username = credentials['username']
api_key = credentials['api_key']
get_url = "http://dis-demo2.cablelabs.com/api/v1/data_distribution_resource/?username="+username+"&api_key="+api_key
response = requests.get(url=get_url)
print response.json()
