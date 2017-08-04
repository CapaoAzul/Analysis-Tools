from tkinter import *
from tkinter.ttk import *

main_window = Tk()

notebook = Notebook(main_window)
frame1 = Frame(notebook)
frame2 = Frame(notebook)
notebook.add(frame1, text='One')
notebook.add(frame2, text='Two')

main_window.mainloop()







