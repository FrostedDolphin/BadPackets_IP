import tweepy
import pandas as pd
import re
import requests
import sys
import json
import time
from datetime import date
import os 

##################################
###### Definitions and such ######
##################################

consumer_key = <TWEEPY CONSUMER KEY>
consumer_secret = <TWEEPTY CONSUMER SECRET>
access_token = <TWEEPY ACCESS TOKEN>
access_token_secret = <TWEEPY TOKEN SECRET>
db1 = 'C:\\Users\\Test\\Python\\blacklist.text'
#db2 = 'C:\\Users\\Test\\Python\\ThreatHunt.txt'
today = str(date.today())
headers = {
"key": '{{<GREYNOISE API>}}'
    }

################################
###### Tweepy API OAuthV1 ######
################################

auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_token_secret)

##############################################################################
###### Gets last 20 tweets from @bad_packets Twitter and parses for IPs ######
##############################################################################

api = tweepy.API(auth,wait_on_rate_limit=True)
user = api.get_user(screen_name='bad_packets')
pattern = "\d\d?\d?\.\d\d?\d?\.\d?\d?\d\.\d\d?\d?"
string = str(api.user_timeline(screen_name='bad_packets',include_rts=False,count=20))
obj1 = re.findall(pattern , string)

########################################################
###### Deduplicates all previously recognized IPs ######
########################################################

dedup = list()
for item in obj1:
    if item not in dedup:
        dedup.append(item)

def db_check():

    #################################################
    ### Creates blacklist file if it doesnt exist ###
    #################################################

    if not os.path.exists(db1):
        open(db1, 'w').close()

    for item in dedup:

        #file2 = open(db2, 'a')
        #file2.write(f'"{item}"'+ " OR ")
        #file2.close()

        with open(db1) as file:
            df = file.read()

            ############################################################################################
            #### Integrates with Greynoise to check if IP belongs to services that shant be blocked ####
            ############################################################################################

            if item not in df:
                url = "https://api.greynoise.io/v3/community/{}".format(item)
                response = requests.request("GET", url, headers=headers)
                json_data = response.json()
                GNR = json_data['riot']
                #print(str(GNR))
                if str(GNR) == 'False': 
                    file1 = open(db1, 'a')
                    file1.write(item+"\n")
                    file1.close()


print('Indicators found:')
print(*dedup, sep='\n')
#file2 = open(db2, 'w')
#file2.write("_SourceCategory=seclogs* ")
#file2.close()
db_check()
