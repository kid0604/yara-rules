rule Linux_Trojan_BPFDoor_1a7d804b
{
	meta:
		author = "Elastic Security"
		id = "1a7d804b-9d39-4855-abe9-47b72bd28f07"
		fingerprint = "e7f92df3e3929b8296320300bb341ccc69e00d89e0d503a41190d7c84a29bce2"
		creation_date = "2022-05-10"
		last_modified = "2022-05-10"
		threat_name = "Linux.Trojan.BPFDoor"
		reference_sample = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.BPFDoor malware"
		filetype = "executable"

	strings:
		$a1 = "getshell" ascii fullword
		$a2 = "/sbin/agetty --noclear tty1 linux" ascii fullword
		$a3 = "packet_loop" ascii fullword
		$a4 = "godpid" ascii fullword
		$a5 = "ttcompat" ascii fullword
		$a6 = "decrypt_ctx" ascii fullword
		$a7 = "rc4_init" ascii fullword
		$b1 = { D0 48 89 45 F8 48 8B 45 F8 0F B6 40 0C C0 E8 04 0F B6 C0 C1 }

	condition:
		all of ($a*) or 1 of ($b*)
}
