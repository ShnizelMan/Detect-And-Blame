# Detect-And-Blame
The Detect And Blame (DAB for short) is a small python script i wrote to scan a folder and its sub-folders , convert it into a csv that contain a sha256 hash and path , and bulk hash it slowly to VT using the free API and returns a Blame csv

### inspiration
largely inspired from [srinivas946's]( https://gist.github.com/srinivas946/36befcf909093d3a91f2acea72300312
 "Click to view his great code") class.
 using his class, converting it to my use,and semi-automate the process using a PS script.
 
 ## Usage
 use `Scan_withSystem.bat` **to scan** your Desktop folder with system permission to make sure that you won't miss a file!
 Change your destenation folder by editing `get_hashes.ps1`.
 
 To **send your hashs to VT** just use `csvToVirusTotal.py` , **but first you need to put your *API key* .** just register to the site
 and you will receive the free tier API key.
 
 ### Free tier VT downsides
 the free tier of VT has a limitation of 4 hashes per minute ,and 500 per day. 
 because of that' i added a one minute pause after every fourth scan do maintain stable scan.
 if you have a premium tier, you can just delete this code segment:
 ```python
for i in tqdm(range(0,60),desc = colored('Script Waiting for 1 Minute','magenta') ):
  time.sleep(1)
```
remove this code in **Line 47** at `csvToVirusTotal.py`
