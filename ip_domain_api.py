import requests
from requests.auth import HTTPBasicAuth
IPs=["92.240.254.110"] # List of IPs here

#IP Part using ALienVault
def alienvaultIp(IP):
    return_dict= {}

    for ip in IP:
        url_ip="https://otx.alienvault.com/api/v1/indicators/IPv4/" + ip + "/geo"
        response=requests.get(url_ip)

        if(response.status_code==200):
            geo_dict=response.json()
            return_dict = {"asn":geo_dict['asn'],'continent':geo_dict['continent_code'],'latitude':geo_dict['latitude'],'longitude':geo_dict['longitude'],'country':geo_dict['country_name']}
            #print(geo_dict)
            """ print("\nAnalyzing the IPs via various sources......\n")
            print("\nIP Address being Analyzed: " + str(ip) + "\n")
            print("ASN: " + geo_dict['asn'])
            print("Continent: " + geo_dict['continent_code'])
            print("Latitude: " + str(geo_dict['latitude']) + " and Longitude: " + str(geo_dict['longitude']))
            print("Country: " + geo_dict['country_name']) """
            return(return_dict)

        else:
            return{"Response_Status": str(response.status_code)}


# IP Part using VirusTotal
def virustotalIp(IP):
    return_dict = {}
    for ip in IP:
        header={ "X-Apikey": "898e54e360cdf32b5714e2d14d3881d6c0274f21a791d972244a4ebe86b2e711"}
        url="https://www.virustotal.com/api/v3/ip_addresses/" + ip
        response_ip_rep=requests.get(url, headers=header)

        if(response_ip_rep.status_code==200):
            ip_rep=response_ip_rep.json()
            #print(ip_rep)
            
            return_dict = {'harmless':str(ip_rep['data']['attributes']['last_analysis_stats']['harmless']),'malicious':str(ip_rep['data']['attributes']['last_analysis_stats']['malicious']),'suspicious':(str(ip_rep['data']['attributes']['last_analysis_stats']['suspicious'])),'undetected':str(ip_rep['data']['attributes']['last_analysis_stats']['undetected'])}
            """
            print("\nIP Reputation from various AVs:\n") 
            print("Harmless: " + str(ip_rep['data']['attributes']['last_analysis_stats']['harmless']))
            print("Malicious: " + str(ip_rep['data']['attributes']['last_analysis_stats']['malicious']))
            print("Suspicious: " + str(ip_rep['data']['attributes']['last_analysis_stats']['suspicious']))
            print("Undetected: " + str(ip_rep['data']['attributes']['last_analysis_stats']['undetected'])) """
            return(return_dict)

        else:
            return{"Response_Status":str(resp_ip_rep.status_code)}
# IP Part Using X-Force
def xforceIp(IP):
    for ip in IP:
        url_ip_history="https://api.xforce.ibmcloud.com/api/ipr/history/" + ip
        auth = HTTPBasicAuth('596dda3c-5763-46f4-a8a0-82b6c27bdb75', 'd83c4aef-fc33-4f6d-874a-61d3a7574735')
        response = requests.get(url_ip_history, auth = auth)

        if(response.status_code==200):
            resp_ip_history=response.json()
            l=len(resp_ip_history['history'])
            #print("\n History of IP: " + str(ip) + "\n")

            for i in range(l):
                return_dict = {'date_of_record':str(resp_ip_history['history'][i]['created']),'location':str(resp_ip_history['history'][i]['geo']['country']),'category':str(resp_ip_history['history'][i]['categoryDescriptions']),'description':str(resp_ip_history['history'][i]['reasonDescription']),'threat_score':str(resp_ip_history['history'][i]['score'])}
                """ print("Date of Record: " + str(resp_ip_history['history'][i]['created']) + "\n",
                "Location: " + str(resp_ip_history['history'][i]['geo']['country']) + "\n", 
                "Category: " + str(resp_ip_history['history'][i]['categoryDescriptions']) + "\n",
                "Description: " + str(resp_ip_history['history'][i]['reasonDescription']) + "\n",
                "Threat Score out of 10 (Higher is More Severe): " + str(resp_ip_history['history'][i]['score'])+"\n")

            print("\n=================================================\n") """
            return(return_dict)

        else:
            return{"Response_Status":str(response.status_code)}



# Domain Part using AlienVault

Domain=["google.com"] # Input domain names here

def alienDomain(Domains):
    for domain in Domains:
        url_domain= "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/geo"
        response_domain=requests.get(url_domain)

        if(response_domain.status_code==200):
            geo_dict=response_domain.json()
            return_dict = {'asn':geo_dict['asn'],'continent':geo_dict['continent_code'],'latitude':str(geo_dict['latitude']),'longitude':str(geo_dict['longitude']),'country':geo_dict['country_name']}
            """ print("\nAnalyzing the Domains via various sources......\n")
            print("\nDomain Name being Analyzed: " + str(domain) + "\n")
            print("ASN: " + geo_dict['asn'])
            print("Continent: " + geo_dict['continent_code'])
            print("Latitude: " + str(geo_dict['latitude']) + " and Longitude: " + str(geo_dict['longitude']))
            print("Country: " + geo_dict['country_name']) """
            return(return_dict)

        else:
            return{"Response_Status":str(response_domain.status_code)}
# Domain/URL Part using X-Force 
# This part below can also analyze the URLs along with the domain names
def xforceDomain(Domains):
    for domain in Domains:
        url_ip_history="https://api.xforce.ibmcloud.com/api/url/" + domain
        auth = HTTPBasicAuth('596dda3c-5763-46f4-a8a0-82b6c27bdb75', 'd83c4aef-fc33-4f6d-874a-61d3a7574735')
        response = requests.get(url_ip_history, auth = auth)
        
        if(response.status_code==200):
            data_url=response.json()
            return_dict={'domain_category':str(data_url['result']['cats']),'threat_score':str(data_url['result']['score']),'description':str(data_url['result']['categoryDescriptions']['Search Engines / Web Catalogues / Portals'])}
            """ print("\nInformation and Threat Level of URLs and Domains\n")
            print("Category of URL/Domain: " + str(data_url['result']['cats']) + "\n",
            "Threat Score: " + str(data_url['result']['score']) + "\n",
            "Description: " + str(data_url['result']['categoryDescriptions']['Search Engines / Web Catalogues / Portals']) + "\n")
            print("\n====================================================\n") """
            return(return_dict)
    else:
        return{"Response_Status":str(response.status_code)}
def googleMapsLink(longi,lati):
    try:
        link= "maps.google.com?q=" + str(longi) + "," + str(lati)
        return(link)
    except:
        print("Error getting link")
print(googleMapsLink(48.6667,19.5))