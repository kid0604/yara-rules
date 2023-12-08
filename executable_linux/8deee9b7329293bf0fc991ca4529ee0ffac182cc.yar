rule Linux_Trojan_Ganiw_b9f045aa
{
	meta:
		author = "Elastic Security"
		id = "b9f045aa-99fa-47e9-b179-ac62158b3fe2"
		fingerprint = "0aaec92ca1c622df848bba80a2f1e4646252625d58e28269965b13d65158f238"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ganiw"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ganiw"
		filetype = "executable"

	strings:
		$a = { E5 57 8B 55 0C 85 D2 74 21 FC 31 C0 8B 7D 08 AB AB AB AB AB AB }

	condition:
		all of them
}
