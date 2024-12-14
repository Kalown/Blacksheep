import os
import hashlib
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import csv

# Function to calculate MD5 hash for a file
def calculate_md5(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

# Function to check the hash on VirusTotal
def check_hash_on_virustotal(md5_hash, api_key):
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{md5_hash}", headers=headers)
    if response.status_code == 200:
        result = response.json()
        if 'data' in result:
            return result['data']['attributes']['last_analysis_results']
        else:
            return None  # No data, file not found in VirusTotal
    else:
        return None  # Error in fetching data

# Function to prompt user to save output as CSV or TXT
def save_output(output_data):
    choice = messagebox.askquestion("Save Output", "Do you want to save the results as a CSV file?")
    
    if choice == 'yes':
        # Save as CSV
        save_as_csv(output_data)
    else:
        # Save as plain text
        save_as_text(output_data)

# Function to save output as CSV
def save_as_csv(output_data):
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['File Name', 'MD5 Hash', 'Path', 'Malicious or Not'])  # Header row
            writer.writerows(output_data)
        messagebox.showinfo("Success", "Results saved as CSV successfully!")

# Function to save output as plain text
def save_as_text(output_data):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, mode='w', encoding='utf-8') as file:
            for line in output_data:
                file.write(line + '\n')
        messagebox.showinfo("Success", "Results saved as text file successfully!")

# Function to process files in the selected directory
def process_directory():
    # Get API Key from the input field
    api_key = api_key_entry.get()
    if not api_key:
        messagebox.showwarning("API Key Required", "Please enter your VirusTotal API key.")
        return

    # Open the folder selection dialog
    directory = filedialog.askdirectory()  
    
    if not directory:
        messagebox.showwarning("No Directory", "Please select a directory.")
        return

    # Clear the results window before processing
    result_text.delete(1.0, tk.END)
    status_label.config(text="Processing... Please wait.", fg="blue")
    browse_button.config(state=tk.DISABLED)
    api_key_entry.config(state=tk.DISABLED)

    # Start the processing in a separate thread to avoid UI freezing
    threading.Thread(target=scan_directory, args=(directory, api_key)).start()

def scan_directory(directory, api_key):
    output_data = []  # To store results
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Calculate MD5 hash for each file
            file_hash = calculate_md5(file_path)
            
            # Output the file path and its MD5 hash in the results window
            result_text.insert(tk.END, f"Checking file: {file_path} || MD5: {file_hash}\n")
            
            # Check the hash in VirusTotal
            analysis_result = check_hash_on_virustotal(file_hash, api_key)
            
            file_name = file
            file_result = f"{file_name} || MD5: {file_hash} || {file_path} || "
            is_malicious = False

            if analysis_result:
                # If VirusTotal returns analysis results
                result_lines = []
                for engine, result in analysis_result.items():
                    result_lines.append(f"Engine: {engine} - {result['category']}")
                    if result['category'] == 'malicious':
                        is_malicious = True
                
                if is_malicious:
                    file_result += "Malicious"
                else:
                    file_result += "Clean"
                
                for line in result_lines:
                    result_text.insert(tk.END, f"  {line}\n")
            else:
                result_text.insert(tk.END, f"  {file_path} not found in VirusTotal database.\n")
                
            result_text.insert(tk.END, "-" * 80 + "\n")
            
            # Store the output in list to later save to file
            output_data.append([file_name, file_hash, file_path, "Malicious" if is_malicious else "Clean"])

            # Ensure the window scrolls automatically
            result_text.yview(tk.END)

    # Once all files are processed, update the UI to reflect completion
    status_label.config(text="Processing complete!", fg="green")
    browse_button.config(state=tk.NORMAL)
    api_key_entry.config(state=tk.NORMAL)

    # Ask user if they want to save the results
    save_output(output_data)

# Create the main GUI window
root = tk.Tk()
root.title("File Hash Checker with VirusTotal Integration")
root.geometry("800x600")

# Add a frame for the buttons and result display
frame = tk.Frame(root)
frame.pack(padx=20, pady=20)

# Add a label for API Key input
api_key_label = tk.Label(frame, text="Enter VirusTotal API Key:", font=("Arial", 12))
api_key_label.grid(row=0, column=0, padx=10, pady=10)

# Add a text box for the user to input their API key
api_key_entry = tk.Entry(frame, width=50, show=None)
api_key_entry.grid(row=0, column=1, padx=10, pady=10)

# Add a label for status updates
status_label = tk.Label(frame, text="Welcome! Select a directory to start.", font=("Arial", 12))
status_label.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

# Add a button to browse for a directory
browse_button = tk.Button(frame, text="Browse for Directory", command=process_directory, height=2, width=20)
browse_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

# Add a scrolled text box to display the results
result_text = scrolledtext.ScrolledText(frame, width=80, height=20, wrap=tk.WORD)
result_text.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

# Run the application
root.mainloop()
