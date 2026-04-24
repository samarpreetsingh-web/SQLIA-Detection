import tkinter as tk
from tkinter import messagebox, ttk
from interceptor import intercept_query
from detector import is_suspect_query_ml  
from handler import handle_query
from logger import log_event

window = tk.Tk()
window.title("SQL Injection Detection System")
window.geometry("500x350")

style = ttk.Style(window)
style.theme_use("clam")
style.configure("TLabel", font=("Helvetica", 12))
style.configure("TButton", font=("Helvetica", 12), padding=6)
style.configure("TEntry", font=("Helvetica", 12))


title_label = ttk.Label(window, text="SQL Injection Detection System", font=("Helvetica", 16, "bold"))
title_label.grid(row=0, column=0, columnspan=3, pady=(10, 10))


query_label = ttk.Label(window, text="Enter SQL Query:")
query_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")


query_input = ttk.Entry(window, width=50)
query_input.grid(row=1, column=1, padx=10, pady=5, sticky="we", columnspan=2)


output_label = ttk.Label(window, text="Response:")
output_label.grid(row=2, column=0, padx=10, pady=(10, 5), sticky="nw")


output_text = tk.Text(window, height=8, width=50, font=("Helvetica", 12))
output_text.grid(row=2, column=1, padx=10, pady=(10, 5), sticky="nsew", columnspan=2)

scrollbar = ttk.Scrollbar(window, orient="vertical", command=output_text.yview)
scrollbar.grid(row=2, column=3, pady=(10, 5), sticky="ns")
output_text.config(yscrollcommand=scrollbar.set)


window.columnconfigure(1, weight=1)
window.rowconfigure(2, weight=1)

def process_query():
    query = query_input.get().strip()
    if not query:
        messagebox.showwarning("Warning", "Please enter an SQL query.")
        return

    intercepted_query = intercept_query(query)
    suspect = is_suspect_query_ml(intercepted_query)  
    result = handle_query(suspect, intercepted_query)
    log_event(intercepted_query, suspect)

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"Processed Query:\n{result}")

analyze_button = ttk.Button(window, text="Analyze Query", command=process_query)
analyze_button.grid(row=3, column=0, columnspan=3, pady=15)

window.mainloop()