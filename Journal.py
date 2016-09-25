#!/usr/bin/python
import tkinter as tk
import datetime
from tkinter import *
from tkinter import filedialog
from tkinter import simpledialog
from Crypto.Cipher import AES


TITLE_FONT = ("Helvetica", 18, "bold")

globvar = ''
loadedf = ''


class Journal(tk.Tk):
	def __init__(self, *args, **kwargs):
			tk.Tk.__init__(self, *args, **kwargs)

			container = tk.Frame(self)
			container.pack(side="top", fill="both", expand=True)
			container.grid_rowconfigure(0, weight=1)
			container.grid_columnconfigure(0, weight=1)

			self.frames = {}
			for F in (Menu, PageOne, PageTwo):
				page_name = F.__name__
				frame = F(parent=container, controller=self)
				self.frames[page_name] = frame

				frame.grid(row=0, column=0, sticky="nsew")

			self.show_frame("Menu")

	def show_frame(self, page_name):
			'''Show a frame for the given page name'''
			frame = self.frames[page_name]
			frame.tkraise()

class Menu(tk.Frame):

	def __init__(self, parent, controller):
		tk.Frame.__init__(self, parent)
		self.controller = controller
		label = tk.Label(self, text="Welcome to your Journal", font=TITLE_FONT)
		label.pack(side="top", fill="x", pady=10)
		button1 = tk.Button(self, text="Today", command=lambda: controller.show_frame("PageOne"))
		button2 = tk.Button(self, text="Edit Previous Days", command=lambda: controller.show_frame("PageTwo"))
		QuitButton = tk.Button(self, text="Quit", command=self.quit)
		button1.pack(pady= 15)
		button2.pack(pady= 15)
		QuitButton.pack(pady= 15)


class PageOne(tk.Frame):
	def __init__(self, parent, controller):
			tk.Frame.__init__(self, parent)
			label = tk.Label(self, text="Today", font=TITLE_FONT)
			label.pack(side="top", fill="x", pady=10)
			self.controller = controller
			global globvar
			globvar = tk.Text(self, bg='light gray', fg='black', wrap='word', highlightthickness=0)
			globvar.pack()
			SaveButton = tk.Button(self, text="Save", command=self.save)
			SaveButton.pack(side= LEFT, padx = 80)
			button = tk.Button(self, text="Go Back", command=lambda: controller.show_frame("Menu"))
			button.pack(side= LEFT)
			QuitButton = tk.Button(self, text="Quit", command=self.quit)
			QuitButton.pack(side= LEFT,padx = 80)

	def save(self):
			key = self.getkey()
			filetext = globvar.get("1.0", "end-1c")
			extra = len(filetext) % 16 # has to be a multiple of 16 so add extra space
			if extra > 0:
				filetext = filetext + (' ' * (16 - extra))
			obj = AES.new(key, AES.MODE_CBC, 'This is an IV456')
			ciphertext = obj.encrypt(filetext)
			savelocation = tk.filedialog.asksaveasfilename(title='Please save it to the folder you have saved previous days')
			file1 = open(savelocation, 'wb')
			file1.write(ciphertext)
			file1.close()
	def getkey(self):
		key = tk.simpledialog.askstring('key', 'please enter the decryption key')
		key = key.zfill(16)
		return key


class PageTwo(tk.Frame):

	def __init__(self, parent, controller):
		tk.Frame.__init__(self, parent)
		self.controller = controller
		label = tk.Label(self, text="Previous Days", font=TITLE_FONT)
		label.pack(side="top", fill="x", pady=10)
		OpenButton = tk.Button(self, text="Open",command=self.open)
		OpenButton.pack()
		button = tk.Button(self, text="Go Back",command=lambda: controller.show_frame("Menu"))
		button.pack()

	def open(self):
		cipheredfile = tk.filedialog.askopenfile(title='Open a file', mode='rb')
		ciphertext = cipheredfile.read()
		cipheredfile.close()
		key = self.getkey()
		obj2 = AES.new(key, AES.MODE_CBC, 'This is an IV456')
		decryptedtext = obj2.decrypt(ciphertext)
		global loadedf
		loadedf = decryptedtext
		self.controller.show_frame("PageOne")
		global globvar
		globvar.insert("end", loadedf)

	def getkey(self):
		key = tk.simpledialog.askstring('key', 'please enter the decryption key')
		key = key.zfill(16)
		return key

root = Journal()
root.wm_title("Journal")
root.mainloop()
