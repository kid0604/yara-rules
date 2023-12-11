rule Linux_Trojan_Mirai_77137320
{
	meta:
		author = "Elastic Security"
		id = "77137320-6c7e-4bb8-81a4-bd422049c309"
		fingerprint = "afeedf7fb287320c70a2889f43bc36a3047528204e1de45c4ac07898187d136b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "91642663793bdda93928597ff1ac6087e4c1e5d020a8f40f2140e9471ab730f9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 54 24 01 89 C7 31 F6 31 C9 48 89 A4 24 00 01 00 00 EB 1D 80 7A }

	condition:
		all of them
}
