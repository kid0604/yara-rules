rule Windows_Ransomware_Snake_20bc5abc : beta
{
	meta:
		author = "Elastic Security"
		id = "20bc5abc-c519-47d2-a6de-5108071a9144"
		fingerprint = "e7f1be2bd7e1f39b79ac89cf58c90abdb537ff54cbf161192d997e054d3f0883"
		creation_date = "2020-06-30"
		last_modified = "2021-08-23"
		description = "Identifies SNAKE ransomware"
		threat_name = "Windows.Ransomware.Snake"
		reference = "https://labs.sentinelone.com/new-snake-ransomware-adds-itself-to-the-increasing-collection-of-golang-crimeware/"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$b1 = { 57 12 1A 10 1A 10 1A 10 1A 10 1A 10 1A 10 1A 10 1A 10 1A 10 1A }

	condition:
		1 of ($b*)
}
