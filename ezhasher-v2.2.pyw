try:
    import Tkinter as tk # python2 import
    from tkFileDialog import askopenfilename
except ImportError:
    import tkinter as tk # python3 import
    from tkinter.filedialog import askopenfilename
import hashlib

BLOCKSIZE = 65536

def hasher(fname, ty):
    if ty == "md5":
        hasher = hashlib.md5()
    elif ty == "sha1":
        hasher = hashlib.sha1()
    elif ty == "sha256":
        hasher = hashlib.sha256()
    else:
        raise ValueError('hash type not known!')

    with open(fname, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
            print(".")
    return str(hasher.hexdigest())

class GUI(tk.Frame):
    def __init__(self, master=None, **kwargs):
        self.frame = tk.Frame.__init__(self, master, **kwargs)

        self.algorithm = 'none'

        lbl = tk.Label(self, text="Welcome to the Hash Calculator")
        lbl.pack()
        lbl = tk.Label(self, text="Please enter a file to hash")
        lbl.pack()

        entry_frame = tk.Frame(self)
        entry_frame.pack()
        self.filename_entry = tk.Entry(entry_frame)
        self.filename_entry.pack(side=tk.LEFT)
        browse_button = tk.Button(entry_frame, text='...', command=self.browse)
        browse_button.pack(side=tk.RIGHT)

        btn = tk.Button(self, text="MD5", command=self.set_md5)
        btn.pack()
        btn = tk.Button(self, text="SHA1", command=self.set_sha1)
        btn.pack()
        btn = tk.Button(self, text="SHA256", command=self.set_sha256)
        btn.pack()
        btn = tk.Button(self, text="EXECUTE", command=self.generate_hash)
        btn.pack()

        self.error_label = tk.Label(self, text="[ERR] No Hash Algorithm", bg="red", fg="white")
        self.error_label.pack()
        self.hash_result = tk.Text(self.frame, state='disabled', width=30, height=1)
        self.hash_result.pack(side=tk.BOTTOM)

    def set_md5(self):
        self.algorithm = 'md5'
        self.error_label.config(text="[INFO] Hash Algorithm is md5", bg="blue", fg="white")

    def set_sha1(self):
        self.algorithm = 'sha1'
        self.error_label.config(text="[INFO] Hash Algorithm is sha1", bg="blue", fg="white")
    def set_sha256(self):
        self.algorithm = 'sha256'
        self.error_label.config(text="[INFO] Hash Algorithm is sha256", bg="blue", fg="white")
    def browse(self):
        fname = askopenfilename()
        if fname != '': # not cancelled by user
            self.filename_entry.delete(0, tk.END) # clear entry box
            self.filename_entry.insert(0, fname) # add selected filename

    def generate_hash(self):
        fname = self.filename_entry.get()
        if fname == "":
            self.error_label.config(text="[ERR] You must enter a file to hash!", bg="red", fg="white")
        elif self.algorithm == "none":
            self.error_label.config(text="[ERR] You must select a hashing algorithm!", bg="red", fg="white")
        else:
            hash_result = hasher(fname, self.algorithm)
            self.error_label.config(text="[OK] Hash Generated:", bg="green", fg="black")
            self.update_hash(hash_result)

    def update_hash(self, result):
        self.hash_result.configure(state='normal', bg="green", fg="black", width=len(result))
        self.hash_result.delete('1.0', tk.END)
        self.hash_result.insert('end', result)
        self.hash_result.configure(state='disabled')

def main():
    root = tk.Tk()
    win = GUI(root)
    win.pack()
    root.mainloop()

if __name__ == '__main__':
    main()
