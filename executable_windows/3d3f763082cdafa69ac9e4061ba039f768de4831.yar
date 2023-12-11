rule Windows_Ransomware_Snake_0cfc8ef3 : beta
{
	meta:
		author = "Elastic Security"
		id = "0cfc8ef3-d8cc-4fc0-9ca2-8e84dbcb45bd"
		fingerprint = "4dd2565c42d52f20b9787a6ede9be24837f6df19dfbbd4e58e5208894741ba26"
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
		$d1 = { 96 88 44 2C 1E 96 45 }
		$d2 = { 39 C5 7D ?? 0F B6 34 2B 39 D5 73 ?? 0F B6 3C 29 31 FE 83 FD 1A 72 }

	condition:
		1 of ($d*)
}
