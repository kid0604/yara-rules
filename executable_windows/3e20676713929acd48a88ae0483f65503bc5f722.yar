rule Windows_Ransomware_Nightsky_a7f19411
{
	meta:
		author = "Elastic Security"
		id = "a7f19411-4c28-4cc7-b60c-ef51cb10b905"
		fingerprint = "0f2aac3a538a921b78f7c2521adf65678830abab8ec8b360ac3dddae5fbc4756"
		creation_date = "2022-01-11"
		last_modified = "2022-04-12"
		threat_name = "Windows.Ransomware.Nightsky"
		reference_sample = "1fca1cd04992e0fcaa714d9dfa97323d81d7e3d43a024ec37d1c7a2767a17577"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows.Ransomware.Nightsky"
		filetype = "executable"

	strings:
		$a1 = "\\NightSkyReadMe.hta" wide fullword
		$a2 = ".nightsky" wide fullword
		$a3 = "<h1 id=\"nightsky\"><center><span style=\"color: black; font-size: 48pt\">NIGHT SKY</span></center>" ascii fullword
		$a4 = "URL:https://contact.nightsky.cyou" ascii fullword

	condition:
		2 of them
}
