"""
Disclaimer:
functions ftp_download, 
            find_latest_in_ftp, 
            find_latest_routeviews,
            download_rib_file 
were modified and copied in from pyasn package's utility scripts folder to download the asn DB, can be found here https://github.com/hadiasghari/pyasn/tree/master/pyasn-utils.
"""
from __future__ import print_function, division
import pdftotext
import pandas as pd
import re
from datetime import date, datetime, timedelta
from time import time
from ftplib import FTP
from sys import argv, exit, stdout, version_info
import pyasn
from pyasn import mrtx
from glob import glob
from argparse import ArgumentParser
from urllib.request import urlopen
from geolite2 import geolite2
import os
import argparse

#note: the ip_pattern does not hold for ip_v6, only v4
ip_pattern = re.compile(r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\."
                     r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\."
                     r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\[\.\]"
                     r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])")
#upper case or lower case-only hash is done elsewhere not in regex pattern
hash_pattern = re.compile(r"\b([^\W_-]{40})\b")  
#regrettably this url pattern only holds for abc.cde[.]xx, cde[.]xxx, but not xyz.abc.cde[.]xx 
url_pattern = re.compile(r"\b(([a-zA-Z0-9]{1,63}.)?[^\W_]{1,63}\[\.\][^\W\d_-]{2,3})\b")

def ftp_download(server, remote_dir, remote_file, local_file, print_progress=True):
    """Downloads a file from an FTP server and stores it locally"""
    ftp = FTP(server)
    ftp.login()
    ftp.cwd(remote_dir)
    if print_progress:
        print('Downloading ftp://%s/%s/%s' % (server, remote_dir, remote_file))
    filesize = ftp.size(remote_file)
    with open(local_file, 'wb') as fp:
        def recv(s):
            fp.write(s)
            recv.chunk += 1
            recv.bytes += len(s)
            if recv.chunk % 100 == 0 and print_progress:
                print('\r %.f%%, %.fKB/s' % (recv.bytes*100 / filesize,
                      recv.bytes / (1000*(time()-recv.start))), end='')
                stdout.flush()
        recv.chunk, recv.bytes, recv.start = 0, 0, time()
        ftp.retrbinary('RETR %s' % remote_file, recv)
    ftp.close()
    if print_progress:
        print('\nDownload complete.')


def find_latest_in_ftp(server, archive_root, sub_dir, print_progress=True):
    """Returns (server, filepath, filename) for the most recent file in an FTP archive"""
    if print_progress:
        print('Connecting to ftp://' + server)
    ftp = FTP(server)
    ftp.login()
    months = sorted(ftp.nlst(archive_root), reverse=True)  # e.g. 'route-views6/bgpdata/2016.12'
    filepath = '/%s/%s' % (months[0], sub_dir)
    if print_progress:
        print("Finding most recent archive in %s ..." % filepath)
    ftp.cwd(filepath)
    fls = ftp.nlst()
    if not fls:
        filepath = '/%s/%s' % (months[1], sub_dir)
        if print_progress:
            print("Finding most recent archive in %s ..." % filepath)
        ftp.cwd(filepath)
        fls = ftp.nlst()
        if not fls:
            raise LookupError("Cannot find file to download. Please report a bug on github?")
    filename = max(fls)
    ftp.close()
    return (server, filepath, filename)


def find_latest_routeviews(archive_ipv):
    '''
    find latest file to download
    '''
    archive_ipv = str(archive_ipv)
    assert archive_ipv in ('4', '6', '46', '64')
    return find_latest_in_ftp(server='archive.routeviews.org',
                              archive_root='bgpdata' if archive_ipv == '4' else
                                           'route-views6/bgpdata' if archive_ipv == '6' else
                                           'route-views4/bgpdata',  # 4+6
                              sub_dir='RIBS')

def check_asn_cc(row, asndb, geo):
    '''
    retrieve ASN and country code using pyasn and geolite2
    '''
    if row['ioc_type']=='ip_address':        
        try:
            asn, _ = asndb.lookup(row['value'])
            asn = int(asn)
        except:
            asn = 'not found'
        response = geo.get(row['value'])
        try:
            return (asn, response['country']['iso_code'])
        except:
            return (asn, "not found")
    else:
        return (None, None)

def download_rib_file():
    """
    calls and run function to download asn db
    """
    srvr, rp, fn = find_latest_routeviews('46')
    ftp_download(srvr, rp, fn, fn)
    return

def verify_asn_database(): 
    """
    looks for latest version of ASN file in this folder
    """   
    if any(item == "asn_{}.asn".format(datetime.today().strftime('%Y%m%d')) for item in os.listdir('.')):    
        print ('latest asn file found') 
        return [item for item in os.listdir('.') if item.endswith('.asn')][0]
    if not any((item.startswith("rib.{}".format(datetime.today().strftime('%Y%m%d'))) \
               and item.endswith('.bz2')) for item in os.listdir('.')):        
        print('Today\'s version of DB not found. Will be downloading latest definitions from archive.routeviews.org. Downloading and parsing DB will take around 1 min.') 
        download_rib_file()
    rib_file = sorted([item for item in os.listdir('.') if \
                (item.startswith('rib.{}'.format(datetime.today().strftime('%Y%m%d')))\
                and item.endswith('.bz2'))])[-1]
    prefixes = mrtx.parse_mrt_file(rib_file, print_progress=True,
                                   skip_record_on_error=True)
    mrtx.dump_prefixes_to_file(prefixes, "asn_{}.asn".format(datetime.today().strftime('%Y%m%d'), rib_file))
    return ("asn_{}.asn".format(datetime.today().strftime('%Y%m%d')))  

def extract_ioc(filepath, output_path):
    """
    open pdf, applies regex for url, sha-1 hash and ip address, then applies further checks on ip_address if any
    saves to location output_path
    """
    try:
        with open(filepath,"rb") as f:
            all_found={}
            pdf = pdftotext.PDF(f)
    except:
        raise Exception ("Problem Loading File".format(filepath))    
    for pageNo, pageText in enumerate(pdf):
        page_contents={}
        ip_matches = ip_pattern.findall(pageText)        
        if ip_matches:
            ip_temp=[]
            for item in ip_matches:
                ip_temp.append(".".join(i for i in item))
            page_contents['ip_address'] = ip_temp
        hash_matches = hash_pattern.findall(pageText)
        if hash_matches:
            hash_matches=[item for item in hash_matches if (item.lower()==item) or (item.upper()==item)] #hashes shouldnt have mix of upper and lower cases
            if hash_matches:
                page_contents['hashes'] = hash_matches
        url_matches = url_pattern.findall(pageText)
        if url_matches:
            url_matches = [item.replace('[','').replace(']','') for (item, _) in url_matches]
            page_contents['url'] = url_matches
        if page_contents:
            all_found[pageNo] = page_contents
    if not all_found:
        print("No IOC found in file. End of script.")
        return
    resultant_df =[]
    for key in all_found:
        df = pd.DataFrame([(key, var) for (key, L) in all_found[key].items() for var in L], columns=['ioc_type','value'])
        df['page']=key
        resultant_df.append(df)
    master_df= pd.concat(resultant_df)
    master_df = master_df.drop_duplicates(subset=['value'], keep='last') #notice that ESET-LightNeuron has the same hash defined in 2 places
    if len(master_df[master_df['ioc_type']=='ip_address'])>0: 
        latest_asn = verify_asn_database()
        asndb = pyasn.pyasn(latest_asn) 
        geo = geolite2.reader()
        master_df[['asn','country_code']] = master_df.apply(check_asn_cc, args=(asndb, geo), axis=1, result_type="expand")    
    if len(master_df)>0:
        master_df.to_csv(output_path, index=False)
        print('End of IOC Extraction from pdf. \n {} url, \n {} hash, \n {} ip address \n are found'\
            .format(len(master_df[master_df['ioc_type']=='url']),\
                len(master_df[master_df['ioc_type']=='hashes']),\
                    len(master_df[master_df['ioc_type']=='ip_address'])))
    else:
        print("No IOC has been found and extracted.")
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Q1 information extract script. Specify file path to begin, ie python q1.py ./data_file/Win32_Industroyer.pdf')
    parser.add_argument("input_path", help="input file path", type=str)
    parser.add_argument("-o","--output", help="(optional) destination file path, default will be same location as input", type=str)
    args = parser.parse_args()
    inputs = vars(args)    
    if not os.path.exists(os.path.abspath(inputs['input_path'])):
        raise Exception ("Input File does not exist at {}".format(os.path.abspath(inputs['input_path'])))
    if inputs['output']:
        if os.path.isdir(os.path.abspath(inputs['output'])):
            raise Exception ('Output File Path {} is not a file_path.'.format(os.path.abspath(inputs['output'])))
        if not os.path.exists(os.path.dirname(os.path.abspath(inputs['output']))):
            raise Exception ('Output Directory {} does not exist.'.format(os.path.dirname(os.path.abspath(inputs['output']))))
    else:
        file_name = os.path.basename(os.path.abspath(inputs['input_path']))+'_extracted.csv'
        inputs['output'] = os.path.join(os.path.dirname(os.path.abspath(inputs['input_path'])), file_name)    
    
    extract_ioc(os.path.abspath(inputs['input_path']), os.path.abspath(inputs['output']))



