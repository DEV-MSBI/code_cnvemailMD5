import hashlib

def convert_to_md5(text):
    # Create an MD5 hash object
    md5_hash = hashlib.md5()

    # Convert the text to bytes (required for the hashlib functions)
    text_bytes = text.encode('utf-8')

    # Update the hash object with the text bytes
    md5_hash.update(text_bytes)

    # Get the MD5 hash in hexadecimal representation
    md5_hex = md5_hash.hexdigest()

    return md5_hex

def process_file(filename):
    md5_hashes = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                md5_hashes.append(convert_to_md5(line))
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None
    return md5_hashes

def save_to_file(filename, md5_hashes):
    try:
        with open(filename, 'w') as file:
            for md5_hash in md5_hashes:
                file.write(md5_hash + '\n')
        print(f"MD5 hashes saved to '{filename}' successfully.")
    except Exception as e:
        print(f"Error while saving to file: {e}")

if __name__ == "__main__":
    input_choice = input("Enter '1' for single text conversion or '2' for file processing: ")

    if input_choice == '1':
        input_text = input("Enter the text to convert to MD5: ")
        md5_result = convert_to_md5(input_text)
        print("MD5 hash:", md5_result)
    elif input_choice == '2':
        input_filename = input("Enter the filename to process: ")
        md5_hashes = process_file(input_filename)
        if md5_hashes:
            print("MD5 hashes:")
            #for md5_hash in md5_hashes:
                #print(md5_hash)
            output_filename = input("Enter the filename to save the MD5 hashes: ")
            save_to_file(output_filename, md5_hashes)
    else:
        print("Invalid choice. Please enter '1' or '2'.")
