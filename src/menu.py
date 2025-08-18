import tkinter as tk
from tkinter import Menu

from caesar import Caesar

if __name__ == '__main__':
	root = tk.Tk()
	root.title('Kriptográfiai Algoritmusok Demo')

	menubar = Menu(root)
	root.config(menu=menubar)

	file_menu = Menu(menubar, tearoff=0)
	algo_menu = Menu(menubar, tearoff=0)

	file_menu.add_command(
		label='Exit',
		command=root.destroy
	)

	algo_menu.add_command(
		label='Caesar',
		command=lambda: Caesar.encrypt('szoveg')
	)

	menubar.add_cascade(
		label='File',
		menu=file_menu
	)
	menubar.add_cascade(
		label='Algo',
		menu=algo_menu
	)
	root.mainloop()