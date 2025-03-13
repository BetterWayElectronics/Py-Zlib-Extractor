import os
import zlib
import sys
from colorama import init, Fore, Style
from subprocess import Popen, PIPE, DEVNULL
import re
import threading
from queue import Queue
import ctypes

# Initialize Colorama
init(autoreset=True)

# Global counter for .pyc files
pyc_count = 0
pyc_count_lock = threading.Lock()

def set_window_title(title):
    title_ansi = title.encode('ansi', 'ignore')
    ctypes.windll.kernel32.SetConsoleTitleA(title_ansi)

set_window_title('BwE Py Zlib Extractor')

def print_banner():
    print(Fore.CYAN + "*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*")
    print(Fore.CYAN + "|" + Fore.WHITE + "            __________          __________               " + Fore.CYAN + "|")
    print(Fore.CYAN + "|" + Fore.WHITE + "            \\______   \\ __  _  _\\_   ____/               " + Fore.CYAN + "|")
    print(Fore.CYAN + ":" + Fore.WHITE + "             |    |  _//  \\/ \\/  /|  __)_                " + Fore.CYAN + ":")
    print(Fore.CYAN + "." + Fore.WHITE + "             |    |   \\\\        //       \\               " + Fore.CYAN + ".")
    print(Fore.CYAN + ":" + Fore.WHITE + "  (\\_/)      |______  / \\__/\\__//______  /               " + Fore.CYAN + ":")
    print(Fore.CYAN + "|" + Fore.WHITE + " ( x_x)             \\/" + Fore.CYAN + "Py ZLib Extractor" + Fore.WHITE + "\\/0.0.1           " + Fore.CYAN + "|")
    print(Fore.CYAN + "|" + Fore.WHITE + " (>  >)                                                  " + Fore.CYAN + "|")
    print(Fore.CYAN + "*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-*\n")

print_banner()

print_lock = threading.Lock()
def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

def find_zlib_streams(data):
    signatures = [b'\x78\x9C', b'\x78\xDA']
    streams = []
    for signature in signatures:
        offset = 0
        while True:
            offset = data.find(signature, offset)
            if offset == -1:
                break
            streams.append(offset)
            offset += 2
    return sorted(streams)

def decompress_streams(data, offsets):
    decompressed_data = []
    for offset in offsets:
        try:
            decompressed = zlib.decompress(data[offset:])
            decompressed_data.append((offset, decompressed))
        except zlib.error:
            continue
    return decompressed_data

def scan_for_pyc(data):
    pyc_magic_numbers = [b'\x42\x0d\x0d\x0a']
    for magic_number in pyc_magic_numbers:
        offset = data.find(magic_number)
        if offset != -1:
            header = data[offset:offset+4]
            return True, header
    return False, None

# Check if the decompressed stream starts with a specific header.
# This example uses a special header (15 bytes) as a marker.
def check_header(data):
    expected_header = b'\xE3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00'
    return data.startswith(expected_header)

def choose_pyc_header():
    safe_print("\nChoose A .Pyc Header:")
    safe_print("1. Python 3.8: 55 0D 0D 0A 00 00 00 00 00 00 00 00 00 00 00 00")
    safe_print("2. Python 3.12: CB 0D 0D 0A 00 00 00 00 00 00 00 00 00 00 00 00")
    safe_print("3. Python 3.13: F3 0D 0D 0A 00 00 00 00 00 00 00 00 00 00 00 00")
    choice = input("\nMake A Selection: ")
    if choice.strip() == "1":
        return bytes.fromhex('550D0D0A000000000000000000000000')
    elif choice.strip() == "3":
        return bytes.fromhex('F30D0D0A000000000000000000000000')
    else:
        return bytes.fromhex('CB0D0D0A000000000000000000000000')

def select_file():
    valid_extensions = ('.exe', '.dmp', '.tmp', '.dump', '.bin')
    files = [file for file in os.listdir() if file.lower().endswith(valid_extensions)]
    if not files:
        print("No Supported Files Found In The Current Directory!")
        return None
    else:
        os.system("cls")
        print_banner()
        print("Supported Files Found:\n")
        for i, file in enumerate(files):
            print(f"{i + 1}. {file}")

        choice = input("\nSelect A File To Decompress: ")
        try:
            choice = int(choice)
            if 1 <= choice <= len(files):
                return files[choice - 1]
            else:
                print("Invalid Choice.")
                return None
        except ValueError:
            print("Invalid Input.")
            return None

def process_stream(data, offset, filename, output_folder, py_files, chosen_header):
    global pyc_count
    hex_offset = hex(offset)[2:].upper()
    output_path = os.path.join(output_folder, f"{filename}_0x{hex_offset}.bin")

    with open(output_path, 'wb') as f_out:
        f_out.write(data)
    safe_print(f"{Fore.YELLOW}Decompressed Stream Saved As: {output_path}{Style.RESET_ALL}")

    # If the data has the special header, prepend the chosen header and save as .pyc
    if check_header(data):
        safe_print(f"{Fore.GREEN}Special Header Found In Decompressed Stream {output_path} At Offset: 0x{hex_offset}{Style.RESET_ALL}")
        temp_pyc_path = os.path.join(output_folder, f"{filename}_0x{hex_offset}.pyc")
        with open(temp_pyc_path, 'wb') as temp_pyc:
            temp_pyc.write(chosen_header + data)
        with pyc_count_lock:
            pyc_count += 1

        try:
            decompile_process = Popen(['pydumpck', temp_pyc_path], stdout=PIPE, stderr=DEVNULL)
            stdout, _ = decompile_process.communicate()

            if "decompile bytecode by pycdc success on file" in stdout.decode():
                match = re.search(r"# Embedded File Name: (.+)", stdout.decode())
                if match:
                    embedded_filename = match.group(1).strip()
                    output_py_path = os.path.join(output_folder, embedded_filename)
                    with open(output_py_path, 'w') as f_out:
                        f_out.write(stdout.decode())
                    py_files.append(output_py_path)
                    safe_print(f"{Fore.GREEN}Decompilation Successful: {output_py_path}{Style.RESET_ALL}")
            else:
                safe_print(f"{Fore.RED}Decompilation Failed: {temp_pyc_path}{Style.RESET_ALL}")
        except Exception as e:
            safe_print(f"{Fore.RED}Decompilation Failed: {temp_pyc_path}{Style.RESET_ALL}")

def worker(data, offsets_queue, filename, output_folder, py_files, chosen_header):
    while True:
        offset = offsets_queue.get()
        if offset is None:
            break
        decompressed_streams = decompress_streams(data, [offset])
        for offset, stream in decompressed_streams:
            process_stream(stream, offset, filename, output_folder, py_files, chosen_header)
        offsets_queue.task_done()

def main():
    selected_file = select_file()
    if selected_file:
        # Prompt the user to choose a pyc header (default is Python 3.12)
        chosen_header = choose_pyc_header()
        filepath = os.path.join(os.getcwd(), selected_file)
        filename, _ = os.path.splitext(selected_file)
        output_folder = os.path.join(os.getcwd(), f"{filename}_Decompressed")
        os.makedirs(output_folder, exist_ok=True)

        with open(filepath, 'rb') as f:
            data = f.read()

        offsets = find_zlib_streams(data)
        offsets_queue = Queue()
        py_files = []
        for offset in offsets:
            offsets_queue.put(offset)

        os.system("cls")
        print_banner()

        num_threads = min(10, len(offsets))
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=worker, args=(data, offsets_queue, filename, output_folder, py_files, chosen_header))
            thread.start()
            threads.append(thread)

        offsets_queue.join()

        for _ in range(num_threads):
            offsets_queue.put(None)

        for thread in threads:
            thread.join()

        # List the created .py files
        if py_files:
            safe_print(f"\n{Fore.CYAN}Decompiled Python Files:{Style.RESET_ALL}")
            for py_file in py_files:
                print(f"{Fore.WHITE}{py_file}{Style.RESET_ALL}")
        else:
            safe_print(f"\n{Fore.RED}No Python Files Were Decompiled.{Style.RESET_ALL}")

        safe_print(f"\n{Fore.CYAN}Total .Pyc Files Extracted: {pyc_count}{Style.RESET_ALL}")

    print("\nPress Enter to Exit...")
    input()
    sys.exit(1)

if __name__ == '__main__':
    main()
