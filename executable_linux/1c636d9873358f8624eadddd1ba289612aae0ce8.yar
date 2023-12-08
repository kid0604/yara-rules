rule Linux_Trojan_Xorddos_93fa87f1
{
	meta:
		author = "Elastic Security"
		id = "93fa87f1-ec9d-4b3b-9c9a-a0b80963f41f"
		fingerprint = "3b53e54dfea89258a116dcdf4dde0b6ad583aff08d626c02a6f1bf0c76164ac7"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "165b4a28fd6335d4e4dfefb6c40f41f16d8c7d9ab0941ccd23e36cda931f715e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { 03 87 44 24 04 89 44 24 04 8B 04 24 8D 64 24 04 8B 00 9C 83 }

	condition:
		all of them
}
