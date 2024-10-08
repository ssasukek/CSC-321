# import matplotlib.pyplot as plt
# import subprocess
# import re

# def openssl_cmd(cmd):
#     result = subprocess.run(['openssl', 'speed', 'rsa'], capture_output=True, text=True)
#     return result.stdout
#     # """Runs a given OpenSSL command and returns the output as a string."""
#     # try:
#     #     result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
#     #     return result.stdout
#     # except subprocess.CalledProcessError as e:
#     #     print(f"Error executing command: {cmd}")
#     #     print(e.stderr)
#     #     return None


# def parse_aes_result(output):
#     throughput = []
#     block_sizes = []

#     lines = output.splitlines()
#     for line in lines:
#         match = re.search(r"(\d+)\s+bytes\s+:\s+(\d+)", line)
#         if match:
#             block_size = int(match.group(1))
#             throughput_value = int(match.group(2))
#             block_sizes.append(block_size)
#             throughput.append(throughput_value)
    
#     return block_sizes, throughput

# # plots the aes performance - aes_performance.png
# def plt_aes_result(result):
#     block_sizes, throughput = parse_aes_result(result)

#     plt.figure(figsize=(20,15))
#     plt.plot(throughput, block_sizes, label = "AES Throughput", marker = 'o')
#     plt.xlabel("Block Size (bytes)")
#     plt.ylabel("Throughput (operation per second)")
#     plt.title("AES Block Size vs. Throughput for the various AES key sizes")
#     plt.legend()
#     plt.grid(True)
#     plt.savefig("aes_performance.png")
#     plt.show()


# def parse_rsa_result(output):
#     throughput = []
#     key_sizes = []

# # plots the rsa performance - rsa_performance.png
# def plt_rsa_result(result):
#     key_sizes, throughput = parse_rsa_result(result)

#     plt.figure(figsize=(20,15))
#     plt.plot(throughput, key_sizes, label = "RSA Throughput", marker = 'o')
#     plt.xlabel("Key Size (bits)")
#     plt.ylabel("Throughput (operation per second)")
#     plt.title("RSA Key Size vs. Throughput for each RSA function")
#     plt.legend()
#     plt.grid(True)
#     plt.savefig("rsa_performance.png")
#     plt.show()


# if __name__ == "__main__":
#     aes_command = ["openssl", "speed", "aes-256-cbc"]
#     aes_results = openssl_cmd(aes_command)
#     plt_aes_result(aes_results)


import matplotlib.pyplot as plt
import subprocess
import re


def plot(data, title, xlabel, ylabel):
    for key_size, throughput in data.items():
        plt.plot(throughput, label=f'{key_size}-bit')

    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.legend()
    plt.grid(True)
    plt.savefig(f"{title}.png")


def run_aes():
    result = subprocess.run(['openssl', 'speed', 'aes'], capture_output=True, text=True)
    output = result.stdout
    data = {}

    regex = re.compile(r'aes-\d{3}-cbc\s+([\d\.]+k)\s+([\d\.]+k)\s+([\d\.]+k)\s+([\d\.]+k)\s+([\d\.]+k)')
    for match in regex.finditer(output):
        key_size = match.group(0).split('-')[1]
        throughput = [float(value.replace('k', '')) for value in match.groups()]
        data[key_size] = throughput

    plot(data, "AES", "Block Size (bytes)", "Throughput (signatures/sec)")


def run_rsa():
    result = subprocess.run(['openssl', 'speed', 'rsa'], capture_output=True, text=True)
    output = result.stdout
    data = {}

    regex = re.compile(r'rsa\s+(\d+)\s+bits\s+[\d\.]+s\s+[\d\.]+s\s+([\d\.]+)\s+([\d\.]+)')
    for match in regex.finditer(output):
        key_size = match.group(1)  # RSA key size (e.g., 512, 1024, 2048, etc.)
        sign_per_sec = float(match.group(2))  # Signatures per second
        verify_per_sec = float(match.group(3))  # Verifications per second

    data[key_size] = (sign_per_sec, verify_per_sec)  # Store as a tuple (sign, verify)

    plot(data, "RSA", "Key Size (bits)", "Throughput (signatures/sec)")


if __name__ == '__main__':
    run_aes()
    run_rsa()