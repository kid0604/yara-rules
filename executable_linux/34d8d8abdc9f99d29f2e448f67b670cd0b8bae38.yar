rule Linux_Trojan_BPFDoor_8453771b
{
	meta:
		author = "Elastic Security"
		id = "8453771b-a78f-439d-be36-60439051586a"
		fingerprint = "b9d07bda8909e7afb1a1411a3bad1e6cffec4a81eb47d42f2292a2c4c0d97fa7"
		creation_date = "2022-05-10"
		last_modified = "2022-05-10"
		threat_name = "Linux.Trojan.BPFDoor"
		reference_sample = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.BPFDoor malware"
		filetype = "executable"

	strings:
		$a1 = "[-] Spawn shell failed." ascii fullword
		$a2 = "[+] Packet Successfuly Sending %d Size." ascii fullword
		$a3 = "[+] Monitor packet send." ascii fullword
		$a4 = "[+] Using port %d"
		$a5 = "decrypt_ctx" ascii fullword
		$a6 = "getshell" ascii fullword
		$a7 = "getpassw" ascii fullword
		$a8 = "export %s=%s" ascii fullword

	condition:
		all of them
}
