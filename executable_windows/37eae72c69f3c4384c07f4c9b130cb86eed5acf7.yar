rule Windows_Ransomware_Ragnarok_1cab7ea1 : beta
{
	meta:
		author = "Elastic Security"
		id = "1cab7ea1-8d26-4478-ab41-659c193b5baa"
		fingerprint = "e2a8eabb08cb99c4999e05a06d0d0dce46d7e6375a72a6a5e69d718c3d54a3ad"
		creation_date = "2020-05-03"
		last_modified = "2021-08-23"
		description = "Identifies RAGNAROK ransomware"
		threat_name = "Windows.Ransomware.Ragnarok"
		reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = ".ragnarok" ascii wide fullword

	condition:
		1 of ($c*)
}
