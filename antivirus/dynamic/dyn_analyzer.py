import subprocess
import sys

def analyze_file(file_path):
	score = 0
	suspicious_system_syscalls = ['setuid', 'setgid', 'chmod','fchmod','chown','fchown']
	network_syscalls = ['bind', 'connect']

	strace_cmd = ['strace', '-f', file_path]

	try:
		print(f"Running {file_path} under strace...")
		proc = subprocess.Popen(strace_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		_, stderr = proc.communicate()
		strace_output = stderr.decode()


		for syscall in network_syscalls:
			if syscall in strace_output:
				score += 3
				
		for syscall in suspicious_system_syscalls:
			if syscall in strace_output:
				score += 7
				print(syscall)
		
		print(f"score = {score}")
	except Exception as e:
		print(f"Error running file with strace: {e}")

if __name__ == "__main__":

	file_path = sys.argv[1]
	analyze_file(file_path)