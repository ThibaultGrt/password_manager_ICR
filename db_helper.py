import pandas
import csv
from Crypto.PublicKey import RSA
import os


passwords_path = "passwords/"
public_path = "public/"
private_path = "private/"
shared_from_path = "shared_from/"
shared_to_path = "shared_to/"

def initialize_db():
    with open('db.csv', 'w', newline='') as fp :
        writer = csv.writer(fp)
        writer.writerow(['username','fingerprint','master_key_salt','cipher_passwords_key'])

def initialize_user_file(username):
    file_path = passwords_path+username+'_WS.csv'
    with open(file_path, 'w', newline='') as fp :
        writer = csv.writer(fp)
        writer.writerow(['website','cipher_password'])

def initialize_shared(username):
    file_path = shared_from_path+username+'_shared.csv'
    with open(file_path, 'w', newline='') as fp :
        writer = csv.writer(fp)
        writer.writerow(['receiver','site'])
    file_path = shared_to_path+username+'_shared.csv'
    with open(file_path, 'w', newline='') as fp :
        writer = csv.writer(fp)
        writer.writerow(['sender','site','enc_password'])


def initialize_files(user):
    initialize_user_file(user)
    initialize_shared(user)

## GETTERS ##

def get_userlist():
    username_list = pandas.read_csv('./db.csv', usecols=['username'])
    return username_list['username']


def get_from_user(username, type):
    file = pandas.read_csv('./db.csv', usecols=['username',type])
    for id, row in file.iterrows():
        if row['username'] == username:
            return row[type]
    raise ValueError("There is no username ", username)

def get_websites_of(user):
    user_file = user+'_WS.csv'
    website_list = pandas.read_csv(passwords_path+user_file, usecols=['website'])
    return website_list['website']


def get_site_password(user, site):
    user_file = user+'_WS.csv'
    file = pandas.read_csv(passwords_path+user_file)
    for id, row in file.iterrows():
        if row['website'] == site:
            return bytes(row['cipher_password'], 'utf-8')
    raise ValueError("There is no website ", site)


def has_user(username):
    return username in set(get_userlist())


def store_account(user, fingerprint, master_key_salt, cipher_passwords_key):
    try:
        with open('db.csv', 'a', newline='', encoding='utf-8') as dbfile:
            writer = csv.writer(dbfile)
            writer.writerow([user, fingerprint, master_key_salt, cipher_passwords_key])
            return True
    except Exception:
        print("Can't write into the DB")


def update_master_password(user, fingerprint, master_key_salt, cipher_passwords_key):
    drop_account_of(user)
    store_account(user, fingerprint, master_key_salt, cipher_passwords_key)
    return True


def drop_account_of(user):
    lineIndex = get_account_index_of(user)
    if lineIndex == -1:
        exit()
    lines = []
    with open("db.csv", 'r') as fp:
        lines = fp.readlines()
    with open("db.csv", 'w') as fp:
    # iterate each line
        for number, line in enumerate(lines):
            if number != lineIndex:
                fp.write(line)


def get_account_index_of(user):
    f = open("db.csv", 'r')
    csvFile = csv.reader(f)
    for line in csvFile:
        if user==line[0]:
            f.close()
            return csvFile.line_num-1
    f.close()
    return -1

def store_password(user, site, cipher_password):
    try:
        user_file = user+'_WS.csv'
        with open(passwords_path+user_file, 'a', newline='', encoding='utf-8') as ufile:
            writer = csv.writer(ufile)
            writer.writerow([site, cipher_password])
            return True
    except Exception:
        print("Can't write into the user file")

def store_public(user, public_key):
    file_path = public_path+user+"_public.pem"
    file_out = open(file_path, "wb")
    file_out.write(public_key)
    file_out.close()

def store_private(user, enc_private_key):
    file_path = private_path+user+"_private"
    file_out = open(file_path, "wb")
    file_out.write(enc_private_key)
    file_out.close()

def get_public(user):
    file_path = public_path+user+"_public.pem"
    public_key = RSA.import_key(open(file_path).read())
    return public_key

def get_private(user):
    file_path = private_path+user+"_private"
    private_key = open(file_path).read()
    return private_key

def store_shared(sender, receiver, site, enc_password):
    receiver_path = shared_to_path+receiver+"_shared.csv"
    sender_path = shared_from_path+sender+"_shared.csv"
    try:
        with open(receiver_path, 'a', newline='', encoding='utf-8') as ufile:
            writer = csv.writer(ufile)
            writer.writerow([sender, site, enc_password])
    except Exception:
        print("Can't write into the receiver file")
    try:
        with open(sender_path, 'a', newline='', encoding='utf-8') as ufile:
            writer = csv.writer(ufile)
            writer.writerow([receiver, site])
    except Exception:
        print("Can't write into the receiver file")

def get_shared_of(user):
    file_path = shared_to_path+user+'_shared.csv'
    list = pandas.read_csv(file_path, usecols=['sender', 'site'])
    return list.values.tolist()


def get_shared_password(receiver, sender, site):
    file_path = shared_to_path+receiver+"_shared.csv"
    file = pandas.read_csv(file_path)
    for id, row in file.iterrows():
        if row['sender'] == sender and row['site'] == site:
            return row['enc_password']
    raise ValueError("There is no website ", site)


if __name__=="__main__":
    print("You're running the db helper")
    print("Theses commands need to be run the first time you use the password manager")
    initialize_db()
    os.mkdir("passwords")
    os.mkdir("private")
    os.mkdir("public")
    os.mkdir("shared_from")
    os.mkdir("shared_to")








