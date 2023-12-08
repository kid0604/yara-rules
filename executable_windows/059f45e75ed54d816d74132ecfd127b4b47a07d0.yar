rule Windows_Ransomware_Ragnarok_5625d3f6 : beta
{
	meta:
		author = "Elastic Security"
		id = "5625d3f6-7071-4a09-8ddf-faa2d081b539"
		fingerprint = "5c0a4e2683991929ff6307855bf895e3f13a61bbcc6b3c4b47d895f818d25343"
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
		$b1 = "prv_ip" ascii fullword
		$b2 = "%i.%i.%i" ascii fullword
		$b3 = "pub_ip" ascii fullword
		$b4 = "cometosee" ascii fullword

	condition:
		all of ($b*)
}
