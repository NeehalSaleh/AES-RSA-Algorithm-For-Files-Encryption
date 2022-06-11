from atexit import register
from cProfile import label
from cgitb import text
import email
from ipaddress import ip_address
from logging import root
from tkinter import*
from tkinter import ttk
from tkinter import font
from tkinter import filedialog
from turtle import bgcolor, left, right, width
import tkinter as tk
import json
from tkinter import messagebox
from nbformat import write
import hashlib
import random 
import rsa
import socket
import os
import time
from cryptography.fernet import Fernet
from PIL import ImageTk, Image
from connection import port_num , IP_add



class login(Tk):
    def __init__(self):
        super().__init__() #inherent from Tk class

        self.geometry("900x700") #size of the page
        self.title('login') 
        self.config(bg='white')
        self.resizable(False,False) # ability to change page size
        titlee= Label(self,text="XSecure",fg='#EF7960',bg='white',font=('Arial',22,'bold'),pady=20)
        titlee.place(x=210,y=50)
        #for the photo
        load = Image.open("./photo/logo.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render,bg='white')
        img.image = render
        img.place(x=50, y=130)



        
        main_frame = Frame(self,bg='#669BBC')
        main_frame.place(x=500,width=400,height=800)
        user_txt = Label(main_frame, text='Username:', fg='white',bg='#669BBC',font=('Courier',13),pady=20).place(x=50,y=100)
        load2 = Image.open("./photo/user2.png")
        render2 = ImageTk.PhotoImage(load2)
        img2 = Label(main_frame, image=render2,bg='#669BBC')
        img2.image = render2
        img2.place(x=50, y=150)
        self.user_name = Entry(main_frame,font=('Courier',14)) #input from the user (user name)
        self.user_name.place(x=120,y=170,width=200,height=30)

        pass_txt= Label(main_frame, text='Password:', fg='white',bg='#669BBC',font=('Courier',13),pady=20).place(x=50,y=250)
        load3 = Image.open("./photo/pass.png")
        render3 = ImageTk.PhotoImage(load3)
        img3 = Label(main_frame, image=render3,bg='#669BBC')
        img3.image = render3
        img3.place(x=50, y=300)
        self.user_pass = Entry(main_frame,font=('Courier',14)) #input from user (password)
        self.user_pass .place(x=120,y=325,width=200,height=30)
                                                                                        #action if button is preesed
        signup = Button(main_frame,text='Sign up',bg='#D86600',bd=0,font=('Courier',15),command=self.signup).place(x=170,y=470,width=100,height=40)
        login_buttun = Button(main_frame,text='Login',bg='#D86600',bd=0,font=('Courier',15),command=self.login).place(x=100,y=400,width=230,height=40)
        pass_txt= Label(main_frame, text='new user?', fg='white',bg='#669BBC',font=('Courier',13),pady=20).place(x=50,y=460)
        self.pass_label = Label(main_frame, fg='red',bg='white',relief=RAISED)
        self.pass_label.pack(pady=110)
        self.pass_label.place(x=100,y=370)


    def signup(self):
        self.destroy()
        signup()
      

    def login(self):
        try:
            record = json.load(open("log_info.json")) #open json file and read the data      
            passwords = [ data["password"] for data in record[str(self.user_name.get())] ] #get password for the user
            salts = [ data["salt"] for data in record[str(self.user_name.get())] ] #get salts for the user
            self.currpass=self.user_pass.get()+str(salts[0]) #add the salts stored in json for the user and add it to input pass
            hash = hashlib.md5(self.currpass.encode()) #hash the password after adding the salt
            hashed = hash.hexdigest()
            if (hashed) in passwords :
                self.destroy()
                home_page()
                
            else:
                self.pass_label.config(text='Incorrect Email or Password,please tyr again')
        except:
                self.pass_label.config(text='Incorrect Email or Password,please tyr again')     


class signup(Tk):
    def __init__(self):
        super().__init__()

        self.geometry("900x700")
        self.title('signup')
        self.config(bg='white')
        self.resizable(False,False)
        titlee= Label(self,text="XSecure",fg='#EF7960',bg='white',font=('Arial',22,'bold'),pady=20).place(x=210,y=50)
        self.load = Image.open("./photo/logo.png")
        self.render = ImageTk.PhotoImage(self.load)
        self.img = Label(self, image=self.render,bg='white')
        self.img.image = self.render
        self.img.place(x=50, y=130)


        
        main_frame = Frame(self,bg='#669BBC')
        main_frame.place(x=500,width=400,height=800)
        #user name
        user_txt = Label(main_frame, text='Username:', fg='white',bg='#669BBC',font=('Courier',13),pady=20).place(x=50,y=100)
        load2 = Image.open("./photo/user2.png")
        render2 = ImageTk.PhotoImage(load2)
        img2 = Label(main_frame, image=render2,bg='#669BBC')
        img2.image = render2
        img2.place(x=50, y=150)
        self.user_name = Entry(main_frame,font=('Courier',14))
        self.user_name.place(x=120,y=170,width=200,height=30)

        #password
        pass_txt= Label(main_frame, text='Password:', fg='white',bg='#669BBC',font=('Courier',13),pady=20).place(x=50,y=250)
        load3 = Image.open("./photo/pass.png")
        render3 = ImageTk.PhotoImage(load3)
        img3 = Label(main_frame, image=render3,bg='#669BBC')
        img3.image = render3
        img3.place(x=50, y=300)
        self.user_pass = Entry(main_frame,font=('Courier',14))
        self.user_pass .place(x=120,y=325,width=200,height=30)


        login_buttun = Button(main_frame,text='Register',bg='#D86600',bd=0,font=('Courier',15),command=self.add_newclient).place(x=100,y=400,width=230,height=40)

    #create new user
    def add_newclient(self):

        self.random_num = random.randint(0,100) #salt number

        #add salt with user input for password
        self.password = str(self.user_pass.get()+str(self.random_num))

        #hash the password
        self.hash = hashlib.md5(self.password.encode())
        self.hashed = self.hash.hexdigest()

        # data formate in json
        self.data_formate = [ {  "password": self.hashed, "salt": self.random_num  } ]

        with open('log_info.json','r+') as file:
            data = json.load(file) #load json python
            data[self.user_name.get()]=(self.data_formate)#insert the data into json file
            file.seek(0)
            json.dump(data, file, indent = 4)

        #create private key and public key
        (self.user_public_key,self.user_private_key) = rsa.newkeys(1025)

        #store private key
        self.privatekey = open(f"./PrivateKey/{self.user_name.get()}PrivateKey.key",'wb')
        self.privatekey.write(self.user_private_key.save_pkcs1('PEM'))
        self.privatekey.close()

        #store public key 
        self.public_key = open(f"./PublicKey/{self.user_name.get()}PublicKey.key",'wb')
        self.public_key.write(self.user_public_key.save_pkcs1('PEM'))
        self.public_key.close()

        self.destroy()
        login()




class home_page(Tk):
    def __init__(self):

        super().__init__()
        self.geometry("900x700")
        self.title('Home')
        self.config(bg='white')
        self.resizable(False,False)
        titlee= Label(self,text="XSecure",fg='#EF7960',bg='white',font=('Arial',22,'bold'),pady=20).place(x=210,y=50)
        self.load = Image.open("./photo/logo.png")
        self.render = ImageTk.PhotoImage(self.load)
        self.img = Label(self, image=self.render,bg='white')
        self.img.image = self.render
        self.img.place(x=50, y=130)
        
        main_frame = Frame(self,bg='#669BBC')
        main_frame.place(x=500,width=400,height=800)

        option_txt = Label(main_frame, text='Please select option:', fg='white',bg='#669BBC',font=('Courier',15,'bold'),pady=20).place(x=90,y=100)
        send_buttun = Button(main_frame,text='Send File',bg='#D86600',bd=0,font=('Courier',15),command=self.send).place(x=100,y=200,width=230,height=40)
        rec_buttun = Button(main_frame,text='Recieve File',bg='#D86600',bd=0,font=('Courier',15),command=self.recieve).place(x=100,y=300,width=230,height=40)

    def send(self):
        self.destroy()
        send()

    def recieve(self):
        self.destroy()
        receiv()
        






class send(Tk):
    def __init__(self):

        super().__init__()
        self.geometry("900x700")
        self.title('Send')
        self.config(bg='white')
        self.resizable(False,False)
        titlee= Label(self,text="XSecure",fg='#EF7960',bg='white',font=('Arial',22,'bold'),pady=20).place(x=210,y=50)
        self.load = Image.open("./photo/logo.png")
        self.render = ImageTk.PhotoImage(self.load)
        self.img = Label(self, image=self.render,bg='white')
        self.img.image = self.render
        self.img.place(x=50, y=130)


        
        main_frame = Frame(self,bg='#669BBC')
        main_frame.place(x=500,width=400,height=800)

        upload_txt = Label(main_frame, text='Upload File.', fg='white',bg='#669BBC',font=('Courier',25,'bold'),pady=0).place(x=100,y=50)
        file_button = Button(main_frame,text='Select file',bg='#D86600',bd=0,font=('Courier',14),command=self.file_explorer_forfile).place(x=110,y=120,width=230,height=40)
        upload_key = Label(main_frame, text='Public Key.', fg='white',bg='#669BBC',font=('Courier',25,'bold'),pady=0).place(x=100,y=230)
        key_button = Button(main_frame,text='Choose Key',bg='#D86600',bd=0,font=('Courier',14),command=self.file_explorer_forkey).place(x=110,y=290,width=230,height=40)


        self.file_lbl = Label(main_frame, fg='#D86600',bg='white',relief=RAISED)
        self.file_lbl.pack(pady=110)
        self.file_lbl.place(x=110,y=170)

        self.key_lbl = Label(main_frame, fg='#D86600',bg='white',relief=RAISED)
        self.key_lbl.pack(pady=110)
        self.key_lbl.place(x=110,y=340)

        send_button = Button(main_frame,text='Send',bg='#D86600',bd=0,font=('Courier',10),command=self.send_data).place(x=180,y=420,width=100,height=40)


        #to open files and choose      
    def file_explorer_forfile(self):
        self.file_path = filedialog.askopenfilename(filetypes=[('All types','*.*')]) #file path
        self.file_lbl.config(text=self.file_path)

        #to open keyss and choose 
    def file_explorer_forkey(self):
        self.key_path = filedialog.askopenfilename(initialdir='./PublicKey/',filetypes=[('All types','*.*')]) #key path
        self.key_lbl.config(text=self.key_path)

    def send_data(self):

        # symmetric key
        AES_key = Fernet.generate_key()
        cipher = Fernet(AES_key)

        # open the file we want to encrypt
        openfile = open(self.file_path,'rb')
        filedata = openfile.read() # read file content

        # encrypt the content 
        encrypte_content = cipher.encrypt(filedata)

        #temp file for encrypted content 
        dataenc = open('encrypted.'+str(os.path.splitext(self.file_path)[1][1:].strip()),'wb')
        dataenc.write(encrypte_content)

        #create socket to send the file
        mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mysocket.bind((IP_add, port_num))
        mysocket.listen(1)
        reciver, addr = mysocket.accept()

        # load user public key
        user_public_key = open(self.key_path,'rb')
        public_key_content = user_public_key.read()
        public_key = rsa.PublicKey.load_pkcs1(public_key_content)

        # encrypt symmetric with user public key
        RSA_encrypting = rsa.encrypt(AES_key,public_key)
        reciver.send(RSA_encrypting)


        #file information
        file_name = 'encrypted.'+str(os.path.splitext(self.file_path)[1][1:].strip())
        file_size = os.path.getsize(file_name)

        # Send file name and its size
        reciver.send(file_name.encode())
        reciver.send(str(file_size).encode())

        # open encrypted file
        with open(file_name, "rb") as file:
            counter = 0
            # send encrypted content to reciever
            while counter <= file_size:
                enc_data = file.read(1024)
                if not (enc_data):
                    break
                reciver.sendall(enc_data)
                counter += len(enc_data)


        mysocket .close()

    


    

class receiv(Tk):
    def __init__(self):

        super().__init__()
        self.geometry("900x700")
        self.title('Recieve')
        self.config(bg='white')
        self.resizable(False,False)
        titlee= Label(self,text="XSecure",fg='#EF7960',bg='white',font=('Arial',22,'bold'),pady=20).place(x=210,y=50)
        self.load = Image.open("./photo/logo.png")
        self.render = ImageTk.PhotoImage(self.load)
        self.img = Label(self, image=self.render,bg='white')
        self.img.image = self.render
        self.img.place(x=50, y=130)


        
        main_frame = Frame(self,bg='#669BBC')
        main_frame.place(x=500,width=400,height=800)

        select_txt = Label(main_frame, text='Select Folder.', fg='white',bg='#669BBC',font=('Courier',25,'bold'),pady=0).place(x=100,y=50)
        choose_button = Button(main_frame,text='Choose Folder',bg='#D86600',bd=0,font=('Courier',14),command=self.select_folder).place(x=110,y=120,width=230,height=40)
        select_key = Label(main_frame, text='Private Key.', fg='white',bg='#669BBC',font=('Courier',25,'bold'),pady=0).place(x=100,y=230)
        key_button = Button(main_frame,text='Choose Key',bg='#D86600',bd=0,font=('Courier',14),command=self.file_explorer_forkey).place(x=110,y=290,width=230,height=40)


        self.folder_lbl = Label(main_frame, fg='#D86600',bg='white',relief=RAISED)
        self.folder_lbl.pack(pady=110)
        self.folder_lbl.place(x=110,y=170)

        self.key_lbl = Label(main_frame, fg='#D86600',bg='white',relief=RAISED)
        self.key_lbl.pack(pady=110)
        self.key_lbl.place(x=110,y=340)

        send_button = Button(main_frame,text='Submit',bg='#D86600',bd=0,font=('Courier',10),command=self.recieve_data).place(x=180,y=420,width=100,height=40)

        #select folder
    def select_folder(self):
        self.folder = filedialog.askdirectory() #folder path
        self.folder_lbl.config(text=self.folder)
        #select key
    def file_explorer_forkey(self):
        self.key_path = filedialog.askopenfilename(initialdir='./PrivateKey/',filetypes=[('All types','*.*')]) #key path
        self.key_lbl.config(text=self.key_path)

    def recieve_data(self):

        connection_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection_sock.connect((IP_add, port_num))
        except:
            print("connection failed.")
            exit(0)

        # recieve AES key
        AES_key = connection_sock.recv(1024)

        # recieve file information
        file_name = connection_sock.recv(100).decode()
        file_size = connection_sock.recv(100).decode()

        # read file
        with open(str(self.folder)+"/"+str(os.path.basename(file_name)), "wb") as file:
            counter = 0
            # recieve file content
            while counter <= int(file_size):
                data = connection_sock.recv(1024)
                if not (data):
                    break
                file.write(data)
                counter += len(data)


        # Closing the socket.
        connection_sock.close()


        #  rsa private key 
        user_privatekey_file = open(self.key_path,'rb')
        privatekey = user_privatekey_file.read()
        user_RSA_key = rsa.PrivateKey.load_pkcs1(privatekey)

        #decrypt aes key 
        AES_key = rsa.decrypt(AES_key,user_RSA_key)
        cipher = Fernet(AES_key)

        #open file
        encrypted_data = open(str(self.folder)+"/"+str(os.path.basename(file_name)),'rb')
        encdata = encrypted_data.read()

        #decrypt content
        mycontent = cipher.decrypt(encdata)

        #write decrypted content
        file = open(self.folder+'/decrypted.'+str(os.path.splitext(file_name)[1][1:].strip().lower()),'wb')
        file.write(mycontent)
        file.close()

        #delete temp file
        os.remove('encrypted.'+str(os.path.splitext(file_name)[1][1:].strip().lower()))


if __name__ == "__main__":
    obj = login()
    obj.mainloop()

