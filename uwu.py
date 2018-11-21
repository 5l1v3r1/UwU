#!/usr/bin/python3
# -*- coding: utf-8 -*-
import pip, os
pkg = ['fabulous', 'configparser', 'hashlib', 'exifread']
for package in pkg:
    try:
        from fabulous import image
        from configparser import ConfigParser
        import hashlib
        import exifread
    except:
        print("Installing Required Modules...")
        pip.main(['install', package])
        from fabulous import image
        from configparser import ConfigParser
        import hashlib
        import exifread

os.system("clear")
    
exiftypes = [
    '.jpg',
    '.jpeg',
    '.tif'
]
malcode = [
    '.exe',
    '.doc',
    '.docx',
    '.docm',
    '.hta',
    '.html',
    '.htm',
    '.js',
    '.jar',
    '.vbs',
    '.vb',
    '.pdf',
    '.sfx',
    '.bat',
    '.dll',
    '.tmp',
    '.py',
    '.msi',
    '.msp',
    '.com',
    '.gadget',
    '.cmd',
    '.vbe',
    '.jse',
    '.ps1',
    '.ps1xml',
    '.ps2',
    '.ps2xml',
    '.psc1',
    '.psc2',
    '.lnk',
    '.inf',
    '.scf',
    '.reg',
    '.rar',
    '.zip',
    '.exe',
    '.bin',
    '.app',
    '.exec',
    '.cer',
    '.csh',
    '.png',
    '.jpg',
    '.jpeg'
]
def colorcute(msg):
    msg = "\33[91m" + msg + "\33[0m"
    return msg
from fabulous import image

uwu = colorcute("[uwu]: ") 
print(image.Image("src/images/welcome.png"))
print(image.Image("src/images/uwu.png"))
print(colorcute("Welcome Senpai").center(74, " "))
print(colorcute("UwU File Scanner").center(74, " "))
print(colorcute("Developed by @maxbridgland").center(74, " "))
print(colorcute("[i] Please Enter The File Location [i]").center(74, " "))
uwu = colorcute("\n[uwu]> ")

def getmd5(abc):
    md5_hash = hashlib.md5()
    with open(abc, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
            md5hash = md5_hash.hexdigest()
    return md5hash

def getsha256(abc):
    sha256_hash = hashlib.sha256()
    with open(abc, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
            sha256hash = sha256_hash.hexdigest()
    return sha256hash

def getexifdata(abc):
    from terminaltables import SingleTable
    exiftable = []
    with open(abc, "rb") as f:
        tags = exifread.process_file(f)
        for tag in tags.keys():
            if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF UserComment'):
                exiftable.append([str(tag), str(tags[tag])])
    table = SingleTable(exiftable)
    table.inner_row_border = True
    print("\33[91m")
    print(table.table)
    print("\33[0m")
    
def setapi():
    config = ConfigParser()
    config['DEFAULT'] = {
            'apikey': ''
    }
    print(colorcute("[!] Enter Virus Total API Key [!]"))
    apikey = input(colorcute(uwu))
    config['DEFAULT']['apikey'] = apikey
    with open('src/configuration/config.ini', 'w') as cf:
        config.write(cf)

def vscan(filename):
    import requests, json
    if os.path.exists('src/configuration/config.ini') == True:
        pass
    else:
        setapi()
    config = ConfigParser()
    config.read('src/configuration/config.ini')
    apikey = config['DEFAULT']['apikey']
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    params = {'apikey': apikey}
    files = {'file': (filename, open(filename, 'rb'))}
    response = requests.post(url, files=files, params=params)
    resp = response.json()
    link = resp['permalink']
    print(colorcute("[i] Scan Link: %s [i]" % link).center(74, " "))
    

def main():
    filename = input(uwu)
    if os.path.exists(filename) == False:
        print(colorcute("[!] Ooops! That file doesn't exist silly! [!]"))
        main()
    else:
        pass
    if "." not in str(filename):
        print(colorcute("[!] Ooops! That's a directory! [!]"))
        main()
    else:
        pass
    filesize = os.path.getsize(filename)
    fileExt = os.path.splitext(filename)
    md5hash = getmd5(filename)
    sha256hash = getsha256(filename)
    print("\33[91m=" * 97)
    print("Filename:          |", filename.center(74, " "), "|")
    print("File Type:         |", fileExt[1].center(74, " "), "|")
    print("File Size [Bytes]: |", str(int(filesize)).center(74, " "), "|")
    print("MD5:               |", md5hash.center(74, " "), "|")
    print("SHA256:            |", sha256hash.center(74, " "), "|")
    print("=" * 97 + "\33[0m")
    if fileExt[1] in exiftypes:
        print(colorcute("[?] Detected .jpeg/.jpg/.tif file. Would you like to read exif data [?]"))
        exifterm = str(input(uwu + colorcute("[y\\n] ")).lower())
        if exifterm == "y":
            print(colorcute("[!] Okay senpai! Reading Data... [!]"))
            getexifdata(filename)
    if fileExt[1] in malcode:
        if filesize <= 33554432:
            print(colorcute("[!] File type could contain malicous code! Would you like to run a scan? [!]\n[!] Warning: Requires you to have API Key from virustotal.com [!]").center(74, " "))
            scanask = str(input(uwu + colorcute("[y\\n] ")).lower())
            if scanask == "y":
                vscan(filename)
                main()
        elif filesize >= 33554432:
            print(colorcute("[i] File Too Large for Virus Scan! [i]").center(""))
main()
