from ast import Str
import csv, requests, time
import string
from tqdm.auto import tqdm
from termcolor import colored

API_KEY = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

# ========================================
#   CHECK HASH VALUES USING VIRUSTOTAL
# ========================================
class Hash_Check:
    
    # ====================================================
    #  LOAD REQUIRED FILES AND PARAMETERS FOR API REQUEST
    # ====================================================
    def __init__(self, read_file_path, write_file_path, api_key, api_url):
        self._read_file_path = read_file_path
        self._write_file_path = write_file_path
        self._api_key = api_key
        self._api_url = api_url
    
    # =============================================================
    #  READ CSV FILE USING CSV MODULE AND RETURN HASH INFORMATION
    # =============================================================
    def read_csv(self):
        hashes_dict =dict()
        with open(self._read_file_path, 'r') as csvfile:
            data_reader = csv.reader(csvfile)  
            next(data_reader) 
            for row in data_reader: 
                hashes_dict[row[2]] = row [1]
            return hashes_dict
        
    # ===================================================
    #  CHECK HASH INFORMATION FROM VIRUSTOTAL USING API
    # ===================================================
    def check_vt(self, hashes_dict):
        store_hash_information = []
        for i,key in tqdm(enumerate(hashes_dict),total=len(hashes_dict),position=0, leave=True):
            if i%4 == 0 and i!=0:
                tqdm.write(colored("Script is backing up...Done!",'grey'))
                with open(self._write_file_path, 'w') as csvfile:
                    data_writer = csv.writer(csvfile)
                    data_writer.writerow(['PATH',"EXTENTION",'SHA1', 'SHA256', 'MD5', 'SCORE'])
                    data_writer.writerows(store_hash_information)          
                for i in tqdm(range(0,60),desc = colored('Script Waiting for 1 Minute','magenta') ):
                    time.sleep(1)
            #print("now ",hashes_dict[key])
            params = {'apikey': self._api_key,'resource': hashes_dict[key]}
            response = requests.get(self._api_url, params=params)
            if response.status_code == 200:
                try:
                    obtained_res = response.json()
                    sha1 = obtained_res['sha1'] 
                    sha256 = obtained_res['sha256']
                    md5 = obtained_res['md5']
                    score = f"{obtained_res['positives']}/{obtained_res['total']}"
                    store_hash_information.append([key,key[key.rfind('.')::] ,sha1, sha256, md5, score])
                except Exception as e:
                    print(colored("FAILD :" + key+"\n",'red'))
                    with open("failscan.csv", 'w') as csvfile:
                        data_writer = csv.writer(csvfile)
                        data_writer.writerow(['PATH', 'SHA256','msg'])
                        data_writer.writerow([key,sha256,str(obtained_res)])          
        return store_hash_information

    # ====================================================
    #  WRITE HAHES RESULT TO CSV FILE USING CSV MODULE
    # ====================================================
    def write_csv(self, data):
        with open(self._write_file_path, 'w') as csvfile:
            data_writer = csv.writer(csvfile)
            data_writer.writerow(['PATH','SHA1', 'SHA256', 'MD5', 'SCORE'])
            data_writer.writerows(data)
            return True

# ==================================
#  PROGRAM EXECUTION STARTS HERE
# ==================================

# CREATE "HASH_CHECK" OBJECT CLASS
hc = Hash_Check(read_file_path='FilesHash.csv', write_file_path='hashes_output.csv', api_key=API_KEY, api_url='https://www.virustotal.com/vtapi/v2/file/report')

# INVOKE "read_csv" METHOD TO READ HASHES FROM CSV
hashes_dict = hc.read_csv()

# INVOKE "check_vt" METHOD TO FETCH HASHES INFORMATION FROM VIRUSTOTAL
hash_result = hc.check_vt(hashes_dict=hashes_dict)

# INVOKE "write_csv" METHOD TO STORE HASH RESULT TO CSV 
confirm = hc.write_csv(data=hash_result)
if confirm is True: print(colored('File Created','green'))
else: print('Not Able to Create a File')