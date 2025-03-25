


import tkinter as tk
from tkinter import messagebox, ttk
from password_generator import PasswordGenerator
from strength_analyzer import PasswordStrengthAnalyzer

class SecurePasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure Password Generator")
        master.geometry("600x700")
        master.configure(bg="#f0f0f0")

        self.password_generator = PasswordGenerator()
        self.strength_analyzer = PasswordStrengthAnalyzer()

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.master, text="Password Length:", bg="#f0f0f0").pack(pady=(10, 0))
        self.length_var = tk.IntVar(value=12)
        length_slider = ttk.Scale(
            self.master, from_=8, to=32, orient='horizontal', variable=self.length_var, length=300
        )
        length_slider.pack(pady=(0, 10))

        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)

        char_frame = tk.Frame(self.master, bg="#f0f0f0")
        char_frame.pack(pady=10)

        tk.Checkbutton(char_frame, text="Uppercase", variable=self.use_uppercase, bg="#f0f0f0").pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(char_frame, text="Lowercase", variable=self.use_lowercase, bg="#f0f0f0").pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(char_frame, text="Digits", variable=self.use_digits, bg="#f0f0f0").pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(char_frame, text="Symbols", variable=self.use_symbols, bg="#f0f0f0").pack(side=tk.LEFT, padx=5)

        generate_btn = tk.Button(
            self.master, text="Generate Password", command=self.generate_password, bg="#4CAF50", fg="white"
        )
        generate_btn.pack(pady=10)

        self.password_var = tk.StringVar()
        password_entry = tk.Entry(
            self.master, textvariable=self.password_var, font=("Courier", 12), width=40, justify='center'
        )
        password_entry.pack(pady=10)

        copy_btn = tk.Button(
            self.master, text="Copy to Clipboard", command=self.copy_to_clipboard, bg="#2196F3", fg="white"
        )
        copy_btn.pack(pady=10)

        tk.Label(self.master, text="Password Strength:", bg="#f0f0f0").pack(pady=(10, 0))
        self.strength_var = tk.StringVar()
        strength_label = tk.Label(self.master, textvariable=self.strength_var, font=("Arial", 10, "bold"), bg="#f0f0f0")
        strength_label.pack(pady=10)

    def generate_password(self):
        char_sets = {
            'uppercase': self.use_uppercase.get(),
            'lowercase': self.use_lowercase.get(),
            'digits': self.use_digits.get(),
            'symbols': self.use_symbols.get()
        }

        password = self.password_generator.generate(
            length=self.length_var.get(), **char_sets
        )

        self.password_var.set(password)
        strength = self.strength_analyzer.analyze(password)
        self.strength_var.set(strength)

    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

def main():
    root = tk.Tk()
    app = SecurePasswordGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
