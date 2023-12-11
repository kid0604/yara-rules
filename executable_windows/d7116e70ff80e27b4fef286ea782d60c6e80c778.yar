rule Windows_Ransomware_Dharma_b31cac3f : beta
{
	meta:
		author = "Elastic Security"
		id = "b31cac3f-6e04-48b2-9d16-1a6b66fa8012"
		fingerprint = "25d23d045c57758dbb14092cff3cc190755ceb3a21c8a80505bd316a430e21fc"
		creation_date = "2020-06-25"
		last_modified = "2021-08-23"
		description = "Identifies DHARMA ransomware"
		threat_name = "Windows.Ransomware.Dharma"
		reference = "https://blog.malwarebytes.com/threat-analysis/2019/05/threat-spotlight-crysis-aka-dharma-ransomware-causing-a-crisis-for-businesses/"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$b1 = "sssssbsss" ascii fullword
		$b2 = "sssssbs" ascii fullword
		$b3 = "RSDS%~m" ascii fullword

	condition:
		3 of ($b*)
}
