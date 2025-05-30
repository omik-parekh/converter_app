import pyperclip
import os
import time
try:
    import speech_recognition as sr
except ImportError:
    sr = None
import gettext
import sys

print("converter.py started at", time.strftime("%Y-%m-%d %H:%M:%S"))

def setup_i18n(lang='en'):
    try:
        translation = gettext.translation('converter', localedir='locale', languages=[lang], fallback=True)
        translation.install()
        return translation.gettext
    except Exception as e:
        print(f"Failed to load translations: {e}")
        return lambda x: x

_ = setup_i18n('en')

MAX_FILE_SIZE = 1_000_000  # 1000 KB in bytes

def validate_binary_chunks(chunks):
    for chunk in chunks:
        if len(chunk) != 8 or not all(c in '01' for c in chunk):
            return False, chunk
    return True, None

def save_to_file(data, filename="output.txt"):
    try:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(data + "\n")
        return _(f"Saved to {filename}")
    except Exception as e:
        return _(f"Failed to write to file: {e}")

def load_from_file(filename):
    try:
        file_size = os.path.getsize(filename)
        if file_size > MAX_FILE_SIZE:
            return None, _(f"File '{filename}' is too large ({file_size} bytes). Maximum size is {MAX_FILE_SIZE} bytes (1000 KB).")
        with open(filename, 'rb') as f:
            data = f.read()
        return data, _(f"Loaded {len(data)} bytes from {filename}")
    except Exception as e:
        return None, _(f"Failed to read from file '{filename}': {e}")

def show_stats(text):
    stats = f"\n=== {_('Summary Stats')} ===\n"
    stats += _(f"Character count: {len(text)}\n")
    stats += _(f"Unique characters: {len(set(text))}\n")
    stats += _(f"Bit length: {len(text.encode('utf-8')) * 8} bits")
    return stats

def xor_encrypt(binary_str, key):
    key_bytes = key.encode('utf-8')
    binary_bytes = bytes(int(b, 2) for b in binary_str.split())
    result = bytearray()
    for i, b in enumerate(binary_bytes):
        result.append(b ^ key_bytes[i % len(key_bytes)])
    return ' '.join(format(b, '08b') for b in result)

def animate_binary(binary_str, output_func=print, delay=0.05):
    chunks = binary_str.split()
    for i, chunk in enumerate(chunks[:1000]):  # Limit to 1000 chunks for display
        output_func(chunk, end=' ', flush=True)
        time.sleep(delay)
        if i % 10 == 9:
            output_func()
    if len(chunks) > 1000:
        output_func("...")
    output_func()

def get_voice_input():
    if not sr:
        return None, _("Voice input not available: speech_recognition library not installed.")
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        print(_("Listening for voice input..."))
        recognizer.adjust_for_ambient_noise(source)
        try:
            audio = recognizer.listen(source, timeout=5)
            text = recognizer.recognize_google(audio)
            print(_(f"Recognized: {text}"))
            return text, None
        except sr.WaitTimeoutError:
            return None, _(f"No speech detected within 5 seconds.")
        except sr.UnknownValueError:
            return None, _(f"Could not understand the audio.")
        except Exception as e:
            return None, _(f"Voice recognition failed: {e}")

def convert_text_to_binary(text, encoding='ascii', encrypt=False, key=''):
    binary = ''.join(format(byte, '08b') for byte in text.encode(encoding))
    if encrypt and key:
        binary = xor_encrypt(binary, key)
    display = ' '.join(binary[i:i+8] for i in range(0, min(10000, len(binary)), 8))
    return display + ("..." if len(binary) > 10000 else ""), binary

def convert_binary_to_text(binary_str, encoding='ascii'):
    binary_chunks = binary_str.strip().split()
    is_valid, invalid = validate_binary_chunks(binary_chunks)
    if not is_valid:
        return None, _(f"Invalid binary chunk: '{invalid}'")
    try:
        bytes_list = [int(b, 2) for b in binary_chunks]
        result = bytes(bytes_list).decode(encoding)
        return result, None
    except Exception as e:
        return None, _(f"Conversion failed: {e}")

def convert_text_to_hex(text, encoding='ascii'):
    result = text.encode(encoding).hex()
    return result[:10000] + ("..." if len(result) > 10000 else ""), result

def convert_hex_to_text(hex_str, encoding='ascii'):
    try:
        result = bytes.fromhex(hex_str).decode(encoding)
        return result[:10000] + ("..." if len(result) > 10000 else ""), result, None
    except Exception as e:
        return None, None, _(f"Hex to text conversion failed: {e}")

def convert_hex_to_binary(hex_str, encrypt=False, key=''):
    try:
        binary = ''.join(format(int(hex_str[i:i+2], 16), '08b') for i in range(0, len(hex_str), 2))
        if encrypt and key:
            binary = xor_encrypt(binary, key)
        display = ' '.join(binary[i:i+8] for i in range(0, min(10000, len(binary)), 8))
        return display + ("..." if len(binary) > 10000 else ""), binary, None
    except Exception as e:
        return None, None, _(f"Hex to binary conversion failed: {e}")

def convert_binary_to_hex(binary_str):
    binary_chunks = binary_str.strip().split()
    is_valid, invalid = validate_binary_chunks(binary_chunks)
    if not is_valid:
        return None, _(f"Invalid binary chunk: '{invalid}'")
    try:
        result = ''.join(format(int(b, 2), '02x') for b in binary_chunks)
        return result[:10000] + ("..." if len(result) > 10000 else ""), result
    except Exception as e:
        return None, _(f"Binary to hex conversion failed: {e}")

def process_file(file_path, encrypt=False, key=''):
    if not os.path.exists(file_path):
        return None, None, _(f"File '{file_path}' does not exist.")
    file_data, message = load_from_file(file_path)
    if not file_data:
        return None, None, message
    binary = ''.join(format(byte, '08b') for byte in file_data)
    if encrypt and key:
        binary = xor_encrypt(binary, key)
    display = ' '.join(binary[i:i+8] for i in range(0, min(10000, len(binary)), 8))
    file_name = os.path.basename(file_path)
    return display + ("..." if len(binary) > 10000 else ""), binary, file_name

def cli_converter():
    history = []
    while True:
        try:
            print("\n=== ", _("Text Converter Menu"), " ===")
            choice = int(input(
                f"1. {_('Char to Binary')}\n"
                f"2. {_('Binary to Char')}\n"
                f"3. {_('Char to Hex')}\n"
                f"4. {_('Hex to Char')}\n"
                f"5. {_('Hex to Binary')}\n"
                f"6. {_('Binary to Hex')}\n"
                f"7. {_('View History')}\n"
                f"8. {_('View Stats')}\n"
                f"9. {_('Batch Mode (any file, max 1000 KB)')}\n"
                f"10. {_('Exit')}\n"
                f"{_('Enter choice (1-10)')}: "
            ).strip())

            if choice in [1, 2, 3, 4, 8]:
                encoding = input(_(f"Choose encoding (ascii / utf-8): ")).strip().lower()
                if encoding not in ['ascii', 'utf-8']:
                    print(_(f"Unsupported encoding. Defaulting to ascii."))
                    encoding = 'ascii'
            else:
                encoding = 'ascii'

            result = ""
            encrypt = False
            if choice in [1, 9]:
                encrypt = input(_(f"Do you want to encrypt the binary output? (y/n): ")).strip().lower() == 'y'

            match choice:
                case 1:
                    use_voice = input(_(f"Use voice input? (y/n): ")).strip().lower() == 'y'
                    if use_voice:
                        msg, error = get_voice_input()
                        if error:
                            print(error)
                            continue
                    else:
                        msg = input(_(f"Enter text: "))
                    key = input(_(f"Enter encryption key: ")) if encrypt else ''
                    display_result, full_result = convert_text_to_binary(msg, encoding, encrypt, key)
                    print(_(f"Binary values:"))
                    animate_binary(display_result)
                    result = f"[Char->Binary] {msg} -> {display_result}"

                case 2:
                    binary_message = input(_(f"Enter binary message (space-separated): "))
                    decoded, error = convert_binary_to_text(binary_message, encoding)
                    if error:
                        print(error)
                    else:
                        print(_(f"Decoded message: {decoded}"))
                        result = f"[Binary->Char] {binary_message} -> {decoded}"

                case 3:
                    msg = input(_(f"Enter text to convert to hex: "))
                    display_result, full_result = convert_text_to_hex(msg, encoding)
                    print(_(f"Hex value: {display_result}"))
                    result = f"[Char->Hex] {msg} -> {display_result}"

                case 4:
                    hex_input = input(_(f"Enter hex string: "))
                    display_result, full_result, error = convert_hex_to_text(hex_input, encoding)
                    if error:
                        print(error)
                    else:
                        print(_(f"Converted text: {display_result}"))
                        result = f"[Hex->Char] {hex_input} -> {display_result}"

                case 5:
                    hex_input = input(_(f"Enter hex string: "))
                    key = input(_(f"Enter encryption key: ")) if encrypt else ''
                    display_result, full_result, error = convert_hex_to_binary(hex_input, encrypt, key)
                    if error:
                        print(error)
                    else:
                        print(_(f"Binary values: {display_result}"))
                        result = f"[Hex->Binary] {hex_input} -> {display_result}"

                case 6:
                    binary_input = input(_(f"Enter binary string (space-separated 8-bit): "))
                    display_result, full_result = convert_binary_to_hex(binary_input)
                    if full_result is None:
                        print(display_result)  # Error message
                    else:
                        print(_(f"Hex value: {display_result}"))
                        result = f"[Binary->Hex] {binary_input} -> {display_result}"

                case 7:
                    print("\n=== ", _("Conversion History"), " ===")
                    if not history:
                        print(_(f"No conversions yet."))
                    for entry in history:
                        print(entry)

                case 8:
                    msg = input(_(f"Enter text to view stats: "))
                    print(show_stats(msg))

                case 9:
                    file_path = input(_(f"Enter the file path for batch processing (any file type, max 1000 KB): ")).strip()
                    key = input(_(f"Enter encryption key: ")) if encrypt else ''
                    display_result, full_result, file_info = process_file(file_path, encrypt, key)
                    if full_result is None:
                        print(file_info)
                        continue
                    file_name = file_info
                    print(_(f"File: {file_name}"))
                    print(_(f"Binary (first 1000 bytes): {display_result}"))
                    history.append(f"[Batch] {file_name} -> {display_result}")
                    continue

                case 10:
                    print(_(f"Exiting the program."))
                    break

                case _:
                    print(_(f"Please enter a number between 1 and 10."))
                    continue

            if result:
                history.append(result)
                try:
                    pyperclip.copy(result.split(' -> ')[-1])
                    print(_(f"Result copied to clipboard."))
                except Exception:
                    print(_(f"Clipboard copy failed. (pyperclip may not be supported in this environment)"))

                save = input(_(f"Do you want to save the result to a file? (y/n): ")).strip().lower()
                if save == 'y':
                    print(save_to_file(result.split(' -> ')[-1]))

        except ValueError:
            print(_(f"Invalid input. Please enter a number between 1 and 10."))
        except KeyboardInterrupt:
            print(_(f"\nProgram interrupted. Exiting."))
            break

if __name__ == "__main__":
    lang = 'en'
    if '--lang' in sys.argv:
        lang_idx = sys.argv.index('--lang')
        if lang_idx + 1 < len(sys.argv):
            lang = sys.argv[lang_idx + 1]
            print(f"Language set to: {lang}")
    _ = setup_i18n(lang)
    cli_converter()
