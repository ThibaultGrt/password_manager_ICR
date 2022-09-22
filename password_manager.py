import helper
import db_helper as db
import clipboard
import printer

## Menu functions ##

def login():
    printer.space()
    printer.title("Login")
    while True:
        user = input("Please enter your username : ")
        mp = input("Please enter your master password : ")
        if helper.verify_login(user, mp):
            try:
                passwords_key = helper.decrypt_passwords_key(user, helper.generate_master_key(user,mp))
                print("Connection sucessfull")
                break
            except Exception as e:
                print("Can't create the master key and/or decrypt the passwords key : ", e)
        else:
            print("Incorrect username or password")
    pwd_manager(user, passwords_key)

def signup():
    printer.space()
    printer.title("Sign up")
    print("/!\ This password need to be a strong one, and you'll need to remember it\n")
    while True:
        username = input("Please enter your username : ") 
        mp = input("Please enter your master password : ")
        mp2 = input("Repeat your master password : ")
        if db.has_user(username):
            print("Error : This username is not available")
        elif mp != mp2:
            print("Error : The new password is not correctly repeat !")
        else:
            if helper.create_account(username,mp):
                print("Account created !")
                break
            else:
                print("Sorry, we can't create your account, please try again")
    main()

def change(): # In order to not re encrypt all passwords, we can generate a random key that we store using a KDF that use the master password
    printer.space()
    printer.title("Change your master password")
    while True:
        username = input("Please enter your username : ")
        mp = input("Please enter your master password : ")
        if helper.verify_login(username, mp):
            break
        else:
            print("Incorrect username or password")
    while True:
        nmp = input("Please enter your NEW master password : ")
        nmp2 = input("Repeat your NEW master password : ")
        if nmp != nmp2:
            print("Error : The new password is not correctly repeat !")
        else:
            if helper.change_password(username, mp, nmp) == True:
                print("Password changed !")
                break
            else:
                print("There is an issue when we try to change your password")
    main()

## Password manager functions ##

def pwd_manager(user, passwords_key):
    printer.space()
    printer.title(user+"'s account")
    while True:
        print("What do you want to do ?")
        print("Access my passwords : 1")
        print("Save a new password : 2")
        print("Access to my shared passwords : 3")
        print("Log out : 4")
        x = input("Your choice (1,2,3 or 4): ")
        if x == "1":
            websites_display(user, passwords_key)
        elif x == "2":
            if save__new_password(user, passwords_key):
                print("Password saved !")
            else:
                print("Error: password not saved")  
        elif x == "3":
            shared_display(user, passwords_key)
        elif x == "4":
            main()
        else:
            print("Your choice is not , retry")



def websites_display(user, passwords_key):
    printer.space()
    printer.title("List of your websites")
    sites = db.get_websites_of(user)
    if len(sites) <= 0:
        print("You don't have passwords yet, go create your first one !")
        return
    else:
        for i in range(0,len(sites)):
            print(i+1, ". ", sites[i])
        print("")
    while True:
        x = input("To display one of theses, enter the right number here or tap 'G' to go back : ")
        if x == "G":
            pwd_manager(user, passwords_key)
        elif not x == "" and int(x) <= len(sites) and sites[int(x)-1] != None:
            website_display(user, sites[int(x)-1], passwords_key)
            break
        else:
            print("Wrong input, retry")
    return
def website_display(user, selected_site, passwords_key):
    printer.space()
    printer.subtitle(selected_site)
    while True:
        print("Show password : 1")
        print("Copy password : 2")
        print("Share password : 3")
        x = input("You choice ? (Tap 'G' to go back) : ")
        if x == "1":
            show_password(user, selected_site, passwords_key)
            printer.space()
        elif x == "2":
            copy_password(user, selected_site, passwords_key)
            printer.space()
        elif x == "3":
            share_password(user, selected_site, passwords_key)
            printer.space()
        elif x == "G":
            websites_display(user, passwords_key)
        else:
            print("I don't understand you choice")
    return

def show_password(user, selected_site, passwords_key):
    printer.space()
    printer.subtitle("Password")
    password = helper.get_password(user, selected_site, passwords_key)
    print("Site :", selected_site)
    print("Password :", password,"\n")
    websites_display(user, passwords_key)

def copy_password(user, selected_site, passwords_key):
    printer.space()
    printer.subtitle("Copy password")
    clipboard.copy(helper.get_password(user, selected_site, passwords_key))
    websites_display(user, passwords_key)

def change_password():
    return

def share_password(user, site, passwords_key):
    printer.space()
    printer.subtitle("Share password")
    while True:
        receiver = input("Enter the username of the user you want to share the password with : ")
        if db.has_user(receiver):
            break
        else:
            print("This user doesn't exist")
    
    if helper.share_password(user, passwords_key, receiver, site):
        print("Password shared !")
        websites_display(user, passwords_key)


def save__new_password(user, passwords_key):
    printer.space()
    printer.title("Saving a new password")
    site = input("Enter the url of the website : ")
    password = input("Enter your password: ")
    printer.space()
    if site in db.get_websites_of(user).tolist():
        print("There is already a password stored for this site")
        return False
    return helper.add_password(user, site, password, passwords_key)


def shared_display(user, passwords_key):
    printer.space()
    printer.title("Shared passwords")
    list = db.get_shared_of(user)
    if len(list) == 0:
        print('There is no shared passwords here')
    else:
        for i in range(0,len(list)):
            print(i+1, ". ", list[i][1]+" - "+list[i][0])
    while True:
        x = input("To display one of theses, enter the right number here or tap 'G' to go back : ")
        if x == "G":
            pwd_manager(user, passwords_key)
        elif not x == "" and int(x) <= len(list) and list[int(x)-1] != None:
            show_shared(user, list[int(x)-1], passwords_key)
            break

def show_shared(user, shared, password_key):
    printer.space()
    printer.subtitle("Show shared password")
    password = helper.rsa_decryption(user, password_key, shared[0], shared[1])
    print("Password : ", password,"\n")

## Menu function ##
def main():
    printer.space()
    printer.title("Welcome to my super password manager !")
    while True:
        print("What do you want to do ? (1: login, 2: create an account, 3: change password)")
        choice = input()
        if choice == "1":
            login()
        elif choice == "2":
            signup()
        elif choice == "3":
            change()
        else:
            print("Wong input, please retry (1,2 or 3)")

if __name__=="__main__":
    main()