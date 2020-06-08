import pandas as pd
import numpy as np
def get_data():
    '''
    avoid importing fields that are not deemed useful
    '''
    columns=['ts','uid','origin_h','origin_p','response_h','response_p',\
                'depth','method','host','uri','referrer','user_agent','request_len','response_len',\
                'status_code','status_msg','info_code','info_msg','filename','tags','username',\
                'password','proxied','origin_fuid','origin_mime_type','response_fuid','response_mime_types']
    usecols = ['ts','uid','origin_h','origin_p','response_h','response_p','depth','method','host','uri',\
                'user_agent','status_code','filename','username']
    df = pd.read_csv('data_files/http.log.gz', compression='gzip', header=None, sep='\t', quoting=3, names = columns, usecols=usecols)
    
    df['origin_p']=df['origin_p'].astype('int')
    df['response_p']=df['response_p'].astype('int')
    df['depth']=df['depth'].astype('int')    
    df['ts'] = pd.to_datetime(df['ts'], unit='s', origin='unix')
    df.loc[df['status_code'] == '-','status_code'] = -1
    df['status_code'] = df['status_code'].astype(int)
    
    return df

def get_raw_data():
    '''
    imports everything from log file
    '''
    columns=['ts','uid','origin_h','origin_p','response_h','response_p',\
                'depth','method','host','uri','referrer','user_agent','request_len','response_len',\
                'status_code','status_msg','info_code','info_msg','filename','tags','username',\
                'password','proxied','origin_fuid','origin_mime_type','response_fuid','response_mime_types']
    df = pd.read_csv('data_files/http.log.gz', compression='gzip', header=None, sep='\t', quoting=3, names = columns)
    
    df['origin_p']=df['origin_p'].astype('int')
    df['response_p']=df['response_p'].astype('int')
    df['depth']=df['depth'].astype('int')
    df['request_len']=df['request_len'].astype('int')
    df['response_len']=df['response_len'].astype('int')
    df['ts'] = pd.to_datetime(df['ts'], unit='s', origin='unix')    
    return df

def describe_df(df):
    '''
    does a analysis of modal values from the dataframe, column by column. A variation of df.info()
    '''
    ans={}
    for col in df.columns:
        col_stats = df[col].value_counts(dropna=False)
        if np.issubdtype(df[col].dtype, np.number):
            ans[col]={'modal value':col_stats.index[0], 'percentage_mode':round((col_stats.iloc[0]/len(df))*100,2), 'nunique':len(col_stats), \
                      'nan_count': df[col].isnull().sum(), 'mem_usage':df[col].memory_usage()/10**6, 'dtype':df[col].dtype, 'min':df[col].min(),\
                     'max':df[col].max()}
        else:        
            ans[col]={'modal value':col_stats.index[0], 'percentage_mode':round((col_stats.iloc[0]/len(df))*100,2), 'nunique':len(col_stats), \
                      'nan_count': df[col].isnull().sum(), 'mem_usage':df[col].memory_usage()/10**6, 'dtype':df[col].dtype}            
    return pd.DataFrame.from_dict(ans, orient='index').fillna('N/A')