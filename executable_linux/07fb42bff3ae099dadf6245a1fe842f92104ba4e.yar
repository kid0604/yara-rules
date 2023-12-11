rule Linux_Trojan_Kinsing_196523fa
{
	meta:
		author = "Elastic Security"
		id = "196523fa-2bb5-4ada-b929-ddc3d5505b73"
		fingerprint = "29fa6e4fe5cbcd5c927e6b065f3354e4e9015e65814400687b2361fc9a951c74"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Kinsing"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Kinsing"
		filetype = "executable"

	strings:
		$a = { 64 65 38 5F 00 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76 35 48 83 }

	condition:
		all of them
}
