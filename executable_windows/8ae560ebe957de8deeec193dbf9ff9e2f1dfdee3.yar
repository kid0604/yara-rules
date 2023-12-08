rule Windows_Ransomware_Ragnarok_efafbe48 : beta
{
	meta:
		author = "Elastic Security"
		id = "efafbe48-7740-4c21-b585-467f7ad76f8d"
		fingerprint = "a1535bc01756ac9e986eb564d712b739df980ddd61cfde5a7b001849a6b07b57"
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
		$a1 = "cmd_firewall" ascii fullword
		$a2 = "cmd_recovery" ascii fullword
		$a3 = "cmd_boot" ascii fullword
		$a4 = "cmd_shadow" ascii fullword
		$a5 = "readme_content" ascii fullword
		$a6 = "readme_name" ascii fullword
		$a8 = "rg_path" ascii fullword
		$a9 = "cometosee" ascii fullword
		$a10 = "&prv_ip=" ascii fullword

	condition:
		6 of ($a*)
}
