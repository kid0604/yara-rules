rule Linux_Trojan_Ddostf_32c35334
{
	meta:
		author = "Elastic Security"
		id = "32c35334-f264-4509-b5c4-b07e477bd07d"
		fingerprint = "f71d1e9188f67147de8808d65374b4e34915e9d60ff475f7fc519c8918c75724"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ddostf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ddostf"
		filetype = "executable"

	strings:
		$a = { 0E 18 41 0E 1C 41 0E 20 48 0E 10 00 4C 00 00 00 64 4B 00 00 }

	condition:
		all of them
}
