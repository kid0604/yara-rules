rule Windows_Ransomware_Snake_550e0265 : beta
{
	meta:
		author = "Elastic Security"
		id = "550e0265-fca9-46df-9d5a-cf3ef7efc7ff"
		fingerprint = "f2796560ddc85ad98a5ef4f0d7323948d57116813c8a26ab902fdfde849704e0"
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
		$a1 = "Go build ID: \"X6lNEpDhc_qgQl56x4du/fgVJOqLlPCCIekQhFnHL/rkxe6tXCg56Ez88otHrz/Y-lXW-OhiIbzg3-ioGRz\"" ascii fullword
		$a2 = "We breached your corporate network and encrypted the data on your computers."
		$a3 = "c:\\users\\public\\desktop\\Fix-Your-Files.txt" nocase
		$a4 = "%System Root%\\Fix-Your-Files.txt" nocase
		$a5 = "%Desktop%\\Fix-Your-Files.txt" nocase

	condition:
		1 of ($a*)
}
