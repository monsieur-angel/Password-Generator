import random
import string
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

# PASSWORD GENERATION FUNCTION
# ------------------------------------------------------------
def generate_password(length, use_upper, use_lower, use_digits, use_symbols):
    characters = ""

    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        return None

    return ''.join(random.choice(characters) for _ in range(length))

# SAVE PASSWORD TO FILE
# ------------------------------------------------------------
def save_password(password):
    with open("saved_passwords.txt", "a") as file:
        file.write(password + "\n")


# ------------------------------------------------------------
def gui_mode():
    def gui_generate():
        try:
            length = int(length_entry.get())
        except:
            messagebox.showerror("Error", "Length must be a number!")
            return

        password = generate_password(
            length,
            upper_var.get(),
            lower_var.get(),
            digits_var.get(),
            symbols_var.get()
        )

        if password is None:
            messagebox.showerror("Error", "Select at least one character type!")
            return

        output_entry.delete(0, tk.END)
        output_entry.insert(0, password)

    def gui_save():
        password = output_entry.get()
        if not password:
            messagebox.showerror("Error", "Generate a password first!")
            return
        save_password(password)
        messagebox.showinfo("Saved", "Password saved successfully!")

    root = tk.Tk()
    root.title("TechX Password Generator")
    root.geometry("420x420")
    root.configure(bg="#0a0f1f")

    # Modern Style
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TLabel", foreground="#00eaff", background="#0a0f1f", font=("Consolas", 12))
    style.configure("TButton", background="#0c1b33", foreground="white", padding=6, font=("Consolas", 11))
    style.map("TButton", background=[("active", "#10223e")])
    style.configure("TCheckbutton", foreground="#00eaff", background="#0a0f1f", font=("Consolas", 11))

    title = ttk.Label(root, text="TECHX PASSWORD GENERATOR", font=("Consolas", 16, "bold"))
    title.pack(pady=10)

    frame = tk.Frame(root, bg="#0a0f1f")
    frame.pack(pady=10)

    ttk.Label(frame, text="Password Length:").grid(row=0, column=0, sticky="w")
    length_entry = ttk.Entry(frame, width=10)
    length_entry.grid(row=0, column=1, padx=10)

    upper_var = tk.BooleanVar()
    lower_var = tk.BooleanVar()
    digits_var = tk.BooleanVar()
    symbols_var = tk.BooleanVar()

    ttk.Checkbutton(frame, text="Include Uppercase", variable=upper_var).grid(row=1, column=0, sticky="w", pady=3)
    ttk.Checkbutton(frame, text="Include Lowercase", variable=lower_var).grid(row=2, column=0, sticky="w", pady=3)
    ttk.Checkbutton(frame, text="Include Numbers", variable=digits_var).grid(row=3, column=0, sticky="w", pady=3)
    ttk.Checkbutton(frame, text="Include Symbols", variable=symbols_var).grid(row=4, column=0, sticky="w", pady=3)

    ttk.Button(root, text="Generate Password", command=gui_generate).pack(pady=15)

    output_entry = ttk.Entry(root, width=35, font=("Consolas", 12))
    output_entry.pack(pady=5)

    ttk.Button(root, text="Save Password", command=gui_save).pack(pady=10)

    root.mainloop()

# CONSOLE MODE
# ------------------------------------------------------------
def console_mode():
    print("\n=== SUPER PASSWORD GENERATOR (CONSOLE MODE) ===")
    length = int(input("Enter password length: "))

    use_upper = input("Include uppercase letters? (y/n): ").lower() == "y"
    use_lower = input("Include lowercase letters? (y/n): ").lower() == "y"
    use_digits = input("Include numbers? (y/n): ").lower() == "y"
    use_symbols = input("Include symbols? (y/n): ").lower() == "y"

    password = generate_password(length, use_upper, use_lower, use_digits, use_symbols)

    if password is None:
        print("Error: No character set selected!")
        return

    print("\nGenerated Password:", password)

    save = input("Save password to file? (y/n): ").lower()
    if save == "y":
        save_password(password)
        print("Password saved to saved_passwords.txt")

# MAIN
# ------------------------------------------------------------
def main():
    gui_mode()  # directly run GUI

if __name__ == "__main__":
    main()
