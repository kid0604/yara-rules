rule Windows_Ransomware_Dharma_e9319e4a : beta
{
	meta:
		author = "Elastic Security"
		id = "e9319e4a-3850-4bad-9579-4b73199a0963"
		fingerprint = "4a4f3aebe4c9726cf62dde454f01cbf6dcb09bf3ef1b230d548fe255f01254aa"
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
		$d = { 08 8B 51 24 8B 45 08 8B 48 18 0F B7 14 51 85 D2 74 47 8B 45 08 8B }

	condition:
		1 of ($d*)
}
