rule Windows_Ransomware_Thanos_e19feca1 : beta
{
	meta:
		author = "Elastic Security"
		id = "e19feca1-b131-4045-be0c-d69d55f9a83e"
		fingerprint = "d6654d0b3155d9c64fd4e599ba34d51f110d9dfda6fa1520b686602d9f608f92"
		creation_date = "2020-11-03"
		last_modified = "2021-08-23"
		description = "Identifies THANOS (Hakbit) ransomware"
		threat_name = "Windows.Ransomware.Thanos"
		reference = "https://labs.sentinelone.com/thanos-ransomware-riplace-bootlocker-and-more-added-to-feature-set/"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "<GetIPInfo>b__"
		$a2 = "<Killproc>b__"
		$a3 = "<Crypt>b__"
		$a4 = "<Encrypt2>b__"
		$b1 = "Your files are encrypted."
		$b2 = "I will treat you good if you treat me good too."
		$b3 = "I don't want to loose your files too"
		$b4 = "/c rd /s /q %SYSTEMDRIVE%\\$Recycle.bin" wide fullword
		$b5 = "\\HOW_TO_DECYPHER_FILES.txt" wide fullword
		$b6 = "c3RvcCBTUUxURUxFTUVUUlkkRUNXREIyIC95" wide fullword
		$b7 = "c3RvcCBNQkFNU2VydmljZSAveQ==" wide fullword
		$b8 = "L0MgY2hvaWNlIC9DIFkgL04gL0QgWSAvVCAzICYgRGVsIA==" wide fullword
		$b9 = "c3RvcCBjY0V2dE1nciAveQ==" wide fullword

	condition:
		(4 of ($a*)) or (3 of ($b*))
}
