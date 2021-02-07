from tkinter import *

root = Tk()
root.title("Tkinter testing")

root.geometry("400x400")


def myClick():
    myLabel = Label(root, text="Click")
    myLabel.pack()


myButton = Button(root, text="Write", command=myClick)
myButton.pack()

root.mainloop()