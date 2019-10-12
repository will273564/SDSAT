import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter

password_provided = "password" # This is input in the form of a string
password = password_provided.encode() # Convert to type bytes
salt = b'M3G3\xc8\xd8\xdfgW\xf62\xda|\x1bA#'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once
print(key)

from cryptography.fernet import Fernet

#key = Fernet.generate_key()
#print(key)

#file = open('key.key', 'rb')
#key = file.read()
#print(key)
#def back():
    #back.destroy()

def reset():
    forgot.destroy()
    reset = tkinter.Tk()
    reset.geometry("960x540")
    reset.title("Will's Password Manager")



def create():
    main.destroy()
    root = tkinter.Tk()
    root.geometry("960x540")
    root.title("Will's Password Manager")

    Title1 = tkinter.Label(root, text="Account Creation:", font=('Ariel', 30))
    usernametext1 = tkinter.Label(root, text="Enter a username:")
    passwordtext1 = tkinter.Label(root, text="Enter a password:")
    username1 = tkinter.Entry(root, width=15)
    password1 = tkinter.Entry(root, show="*", width=15,)
    create1 = tkinter.Button(root, text="Create Account",)
    back1 = tkinter.Button(root, text="Back",)

    username1.place(x=520, y=130)
    password1.place(x=520, y=170)
    usernametext1.place(x=350, y=130)
    passwordtext1.place(x=350, y=170)
    Title1.place(x=365, y=50)
    create1.place(x=560, y=210)
    back1.place(x=350, y= 210)


def forgot():
    main.destroy()
    forgot = tkinter.Tk()
    forgot.geometry("960x540")
    forgot.title("Will's Password Manager")
    Title2 = tkinter.Label(forgot, text="Password Reset", font=('Ariel', 30))
    usernametext2 = tkinter.Label(forgot, text="Enter your username:")
    usernameforgot = tkinter.Entry(forgot, width=15)
    nextb = tkinter.Button(forgot, text="Next", command = reset)

    Title2.place(x=365, y=50)
    usernametext2.place(x=390, y=130)
    usernameforgot.place(x=390, y=170)
    nextb.place(x=440, y=215)




main = tkinter.Tk()
main.geometry("960x540")
main.title("Will's Password Manager")

Title = tkinter.Label(main, text = "Will's Password Manager", font = ('Ariel',30))
username = tkinter.Entry(main, width=15)
password = tkinter.Entry(main, show="*", width=15,)
usernametext = tkinter.Label(main, text = "Username:")
passwordtext = tkinter.Label(main, text = "Password:")
Login = tkinter.Button(main, text = "Login")
forgot = tkinter.Button(main, text = "Forgot Password", command = forgot)
Quit = tkinter.Button(main, text = "Quit", command = quit)
create = tkinter.Button(main, text = "Create Account", command =create)

Title.place(x= 290, y=50)
usernametext.place(x=350, y=135)
passwordtext.place(x=350, y=170)
username.place(x=450, y=130)
password.place(x=450, y=170)
forgot.place(x=400, y=230)
create.place(x=404, y=260)
Login.place(x=290, y=230)
Quit.place(x=575, y=230)

main.mainloop()

def encode(key, string):
    encoded_chars = []
    for i in xrange(len(string)):
        key_c = key[i % len(key)]
        encoded_c = chr(ord(string[i]) + ord(key_c) % 256)
        encoded_chars.append(encoded_c)
    encoded_string = "".join(encoded_chars)
    return base64.urlsafe_b64encode(encoded_string)
