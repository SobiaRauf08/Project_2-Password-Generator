import secrets
import string
import tkinter as tk
from tkinter import messagebox


class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")
        self.root.configure(bg="#f0f8ff")
        self.root.resizable(True, True)

        # Maximize window (works on Windows; fallback size otherwise)
        try:
            self.root.state('zoomed')
        except:
            self.root.geometry("800x600")

        self.setup_ui()

    def setup_ui(self):
        tk.Label(self.root, text="🔐 Password Generator", font=("Arial", 24, "bold"), bg="#f0f8ff").pack(pady=20)

        description = (
            "This tool helps you generate strong, random passwords. "
            "Choose the desired length and whether to include numbers and special characters."
        )
        tk.Label(self.root, text=description, wraplength=800, justify="left", bg="#f0f8ff", font=("Arial", 12)).pack(pady=10)

        frame = tk.Frame(self.root, bg="#f0f8ff")
        frame.pack(pady=15)

        tk.Label(frame, text="Password Length:", font=("Arial", 14), bg="#f0f8ff").grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.entry_length = tk.Entry(frame, font=("Arial", 14), width=10)
        self.entry_length.grid(row=0, column=1, padx=10)
        self.entry_length.insert(0, "12")

        self.var_numbers = tk.BooleanVar(value=True)
        self.var_special = tk.BooleanVar(value=True)

        tk.Checkbutton(self.root, text="Include Numbers (0-9)", font=("Arial", 12),
                       bg="#f0f8ff", variable=self.var_numbers).pack(pady=5)
        tk.Checkbutton(self.root, text="Include Special Characters (!@#$)", font=("Arial", 12),
                       bg="#f0f8ff", variable=self.var_special).pack(pady=5)

        tk.Button(self.root, text="Generate Password", font=("Arial", 14, "bold"),
                  bg="#007bff", fg="white", command=self.generate_password).pack(pady=20)

        tk.Label(self.root, text="Generated Password:", font=("Arial", 14), bg="#f0f8ff").pack()
        self.entry_password = tk.Entry(self.root, font=("Arial", 14), width=40, justify='center')
        self.entry_password.pack(pady=10)

        # Button frame for copy and clear
        button_frame = tk.Frame(self.root, bg="#f0f8ff")
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Copy to Clipboard", font=("Arial", 12),
                  bg="#28a745", fg="white", command=self.copy_to_clipboard).grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Clear", font=("Arial", 12),
                  bg="#dc3545", fg="white", command=self.clear_fields).grid(row=0, column=1, padx=10)

    def generate_password(self):
        try:
            length = int(self.entry_length.get())
            if length < 6:
                messagebox.showwarning("Length Error", "Password length should be at least 6.")
                return

            characters = string.ascii_letters
            if self.var_numbers.get():
                characters += string.digits
            if self.var_special.get():
                characters += string.punctuation

            if not characters:
                messagebox.showwarning("Selection Error", "Please select at least one character type.")
                return

            password = ''.join(secrets.choice(characters) for _ in range(length))

            self.entry_password.delete(0, tk.END)
            self.entry_password.insert(tk.END, password)

        except ValueError:
            messagebox.showerror("Input Error", "Please enter a valid number for password length.")

    def copy_to_clipboard(self):
        password = self.entry_password.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Copy Error", "No password to copy.")

    def clear_fields(self):
        self.entry_password.delete(0, tk.END)
        self.entry_length.delete(0, tk.END)
        self.entry_length.insert(0, "12")


if __name__ == "__main__":
    
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
