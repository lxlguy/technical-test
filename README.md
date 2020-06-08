# Technical-test

Setup environment notes:  
The environment can be replicated by using the conda environment.yml file included in repo.    
```conda env create -f environment.yml```  
__Note:__ One of the python packages might require additional external tools preinstalled if installing on Windows machine, on top of enviroment.yml
If conda install of environment throws exception, download build tools from https://visualstudio.microsoft.com/visual-cpp-build-tools/  
Install the following packages:  
<img src="./assets/installcplusplusbuildtools.png" alt="install c++ build tools" width="600"/>  
This is required for pyasn library.

## Test Question
### A. Automation Scripting  
1. Provide a script to automate the extraction of IP addresses, URLs and hashes from the following cyber threat report.
“Win32/INDUSTROYER A new threat for industrial control system”
(https://www.welivesecurity.com/wp-content/uploads/2017/06/Win32_Industroyer.pdf)  
You can use any open source tools and library to help with the extraction.  

2. With the IP addresses extracted from the pdf document, develop a python script to resolve the autonomous system number (ASN) and Country code for each IP address. The output should be in a CSV file. You can use any open source library to develop the python script.   

This being a text scrapping task, I skimmed through the pdf and looked for patterns that I could apply to the pdf. However, upon looking at Question (B), I realized that the urls in the pdf are of dubious relevance to (B). Upon email clarification, I now understand that threat intelligence reports typically include domain urls, hashes and IP addresses which are of interest to populate a threat database.   
Having better understood the problem statement, I decided to search for more instances of threat reports to ensure that my code scrape for the correct information, at the very least for `welivesecurity.com` PDFs, using a regex based approach.   
From files like:  
1. https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf
2. https://www.welivesecurity.com/wp-content/uploads/2019/08/ESET_Machete.pdf 
3. https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf   

It is observed that in these pdfs:  
1. Hashes are typically SHA-1. We can create a length 40 regex pattern for that, and coupled with the precondition that "SHA-1" is in the same page, to further avoid false alarms. 
2. IP addresses usually have the [.] in between the 3th and 4th octets. This could be to prevent users from accidentally clicking on a working url.
3. URLs are typically of the form:
```
arinas[.]tk
bedrost[.]com
```
These heuristics are used to create the necessary regexes for pt1. For pt2, there were relevant open source libraries that could support the extraction of ASN and country code.  

The script can be found in ./q1.py.

Example usage:  
```python q1.py ./data_files/Win32_Industroyer.pdf``` Outputs a csv in pdf folder.  
```python q1.py ./data_files/Win32_Industroyer.pdf -o ./output.csv``` Defines output location

__Limitations of Approach:__  
The regex does not work for ipv6 addresses.  
There could be SHA-256 or MD-5 hashes but since I did not see it being used in those pdfs, they were not included.
There is a need to occasionally check the pdfs to ensure that there is no information that was missed.


### B. Cyber Threat Analysis  
Provide a write-up for the following.
1. From the extracted IOCs, outline the type of enrichments that can facilitate cyber threat investigation.
2. How would you surface potential additional unknown IOCs from this list of IOCs from the report?  

Response:  
The IOCs would allow investigators to look at relevant parts of the computer networks, ie traffic logs for the IP addresses and URLs and examine system files for the hashes, thus can more confidently identify the cause of the cyber incident. 

2. Additional IOCs for the same malware could be obtained from threat repositories like ```virustotal.com```. I noticed that I was able to key in the SHA-1 hash and from the malware information page, obtain SHA-256 hashes and other information. A scraping effort could be undertaken to collect these additional information, and VirusTotal also offers an low-rate API for free users.  

Research links:  
https://www.securonix.com/data-enrichment-the-key-ingredient-for-siem-success/  
The process of data enrichment adds event and non-event contextual information to security event data in order to transform raw data into meaningful insights. 

The process of data enrichment adds event and non-event contextual information to security event data in order to transform raw data into meaningful insights. Security events can enriched with contextual information from user directories, asset inventory tools (such as CMDB), geolocation tools, third party threat intelligence databases, and a host of other sources.

https://www.sans.org/reading-room/whitepapers/forensics/ioc-indicators-compromise-malware-forensics-34200
https://blog.demisto.com/security-orchestration-use-case-automating-ioc-enrichment 
https://blog.rapid7.com/2019/10/24/accelerating-incident-response-with-threat-intelligence-and-alert-enrichment/
The alert enrichment workflow in InsightIDR leverages open source threat intelligence to look up:

    IPs and domains with WHOIS
    DNS with Dig
    Hash reputation with Cymru
    URL extension with Unshorten.me
This additional context can be extremely helpful during the investigation process to narrow in on the threat actors at play.

https://blogs.gartner.com/anton-chuvakin/2014/02/19/how-to-make-better-threat-intelligence-out-of-threat-intelligence-data/
https://github.com/eCrimeLabs/vt2misp
https://community.sophos.com/kb/en-us/128136#understanding

### B. Cyber Threat Analysis
Analytics Development
1. Design an algorithm to shortlist IPs that could be running reconnaissance activities against an enterprise web server. State any assumption you make in your design. Use the dataset in the following link to develop a prototype of the algorithm.  
https://www.secrepo.com/maccdc2012/http.log.gz

I made use of a rule-based approach to score users in the dataset, using rules that i feel could pick up suspicious behavior. My answer and limited analysis can be found in EDA_v3.ipynb. (EDA_v3.html as backup file) It makes use of code snippets from /src.
I did not modularize the code for Q3 because it is highly specific for the given data format, ie column names would be different for each dataset input etc. I also tried to avoid using specific regex for user_agent nor uri because I feel that they're too specific to dataset.