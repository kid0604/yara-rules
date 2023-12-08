rule Linux_Trojan_Xorddos_f412e4b4
{
	meta:
		author = "Elastic Security"
		id = "f412e4b4-adec-4011-b4b5-f5bb77b65d84"
		fingerprint = "deb9f80d032c4b3c591935c474523fd6912d7bd2c4f498ec772991504720e683"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "0e3a3f7973f747fcb23c72289116659c7f158c604d937d6ca7302fbab71851e9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos with fingerprint f412e4b4"
		filetype = "executable"

	strings:
		$a = { 24 04 C1 E2 05 8B C0 03 C2 9C 83 C5 0F 9D 8D 6D F1 05 0C 00 }

	condition:
		all of them
}
