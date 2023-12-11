rule Linux_Trojan_Xorddos_1d6e10fd
{
	meta:
		author = "Elastic Security"
		id = "1d6e10fd-7404-4597-a97d-cc92849d84f4"
		fingerprint = "bf9d971a13983f1d0fdc8277e76cd1929523e239ce961316fe1f44cbdf0638a8"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "4c7851316f01ae84ee64165be3ba910ab9b415d7f0e2f5b7e5c5a0eaefa3c287"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Xorddos malware based on specific strings"
		filetype = "executable"

	strings:
		$a = { 24 04 9C 83 C5 7B 9D 8D 6D 85 87 54 24 00 9C 83 C5 26 9D 8D }

	condition:
		all of them
}
