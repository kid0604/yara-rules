rule Windows_Trojan_Raccoon_af6decc6
{
	meta:
		author = "Elastic Security"
		id = "af6decc6-f917-4a80-b96d-1e69b8f8ebe0"
		fingerprint = "f9314a583040e4238aab7712ac16d7638a3b7c9194cbcf2ea9b4516c228c546b"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Raccoon"
		reference_sample = "fe09bef10b21f085e9ca411e24e0602392ab5044b7268eaa95fb88790f1a124d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Raccoon"
		filetype = "executable"

	strings:
		$a1 = "A:\\_Work\\rc-build-v1-exe\\json.hpp" wide fullword
		$a2 = "\\stealler\\json.hpp" wide fullword

	condition:
		any of them
}
