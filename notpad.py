import tkinter as tk
from tkinter import filedialog, font, colorchooser, ttk, messagebox

class ProNotepad:
    def __init__(self, root):
        self.root = root
        self.root.title("Pro Notepad")
        self.root.geometry("800x600")

        self.text_area = tk.Text(self.root, wrap="word", undo=True, font=("Arial", 12))
        self.text_area.pack(expand=True, fill="both")
        
        self.menu = tk.Menu(self.root)
        self.root.config(menu=self.menu)
        
        self.file_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open", command=self.open_file)
        self.file_menu.add_command(label="Save", command=self.save_file)
        self.file_menu.add_command(label="Save As", command=self.save_as_file)
        
        self.edit_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="Edit", menu=self.edit_menu)
        self.edit_menu.add_command(label="Copy", command=lambda: self.text_area.event_generate("<<Copy>>"))
        self.edit_menu.add_command(label="Cut", command=lambda: self.text_area.event_generate("<<Cut>>"))
        self.edit_menu.add_command(label="Paste", command=lambda: self.text_area.event_generate("<<Paste>>"))
        self.edit_menu.add_command(label="Undo", command=lambda: self.text_area.event_generate("<<Undo>>"))
        self.edit_menu.add_command(label="Redo", command=lambda: self.text_area.event_generate("<<Redo>>"))
        self.edit_menu.add_command(label="Find & Replace", command=self.find_replace)
        
        self.view_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="View", menu=self.view_menu)
        self.view_menu.add_command(label="Dark Mode", command=self.toggle_dark_mode)
        self.view_menu.add_command(label="Change Font Color", command=self.change_font_color)
        self.view_menu.add_command(label="Change Font Size", command=self.change_font_size)
        
        self.dark_mode = False
        self.current_file = None
    
    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "r", encoding="utf-8") as file:
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert("1.0", file.read())
            self.current_file = file_path
    
    def save_file(self):
        if self.current_file:
            with open(self.current_file, "w", encoding="utf-8") as file:
                file.write(self.text_area.get("1.0", tk.END))
        else:
            self.save_as_file()
    
    def save_as_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(self.text_area.get("1.0", tk.END))
            self.current_file = file_path
    
    def toggle_dark_mode(self):
        if not self.dark_mode:
            self.text_area.config(bg="black", fg="white", insertbackground="white")
            self.dark_mode = True
        else:
            self.text_area.config(bg="white", fg="black", insertbackground="black")
            self.dark_mode = False
    
    def change_font_color(self):
        color = colorchooser.askcolor(title="Choose Font Color")[1]
        if color:
            self.text_area.config(fg=color)
    
    def change_font_size(self):
        new_size = tk.simpledialog.askinteger("Font Size", "Enter Font Size:", minvalue=8, maxvalue=50)
        if new_size:
            current_font = font.nametofont(self.text_area.cget("font"))
            self.text_area.config(font=(current_font.actual()["family"], new_size))
    
    def find_replace(self):
        find_window = tk.Toplevel(self.root)
        find_window.title("Find & Replace")
        find_window.geometry("300x150")
        
        tk.Label(find_window, text="Find: ").grid(row=0, column=0, padx=5, pady=5)
        find_entry = tk.Entry(find_window)
        find_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(find_window, text="Replace: ").grid(row=1, column=0, padx=5, pady=5)
        replace_entry = tk.Entry(find_window)
        replace_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def replace_text():
            find_text = find_entry.get()
            replace_text = replace_entry.get()
            content = self.text_area.get("1.0", tk.END)
            new_content = content.replace(find_text, replace_text)
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert("1.0", new_content)
            find_window.destroy()
        
        tk.Button(find_window, text="Replace", command=replace_text).grid(row=2, columnspan=2, pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = ProNotepad(root)
    root.mainloop()
