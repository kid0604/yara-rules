rule Windows_Ransomware_Dharma_942142e3 : beta
{
	meta:
		author = "Elastic Security"
		id = "942142e3-9197-41c4-86cc-66121c8a9ab5"
		fingerprint = "e8ee60d53f92dd1ade8cc956c13a5de38f9be9050131ba727f2fab41dde619a8"
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
		$a1 = "C:\\crysis\\Release\\PDB\\payload.pdb" ascii fullword

	condition:
		1 of ($a*)
}
