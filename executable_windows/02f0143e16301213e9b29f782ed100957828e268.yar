rule Windows_Trojan_OnlyLogger_b9e88336
{
	meta:
		author = "Elastic Security"
		id = "b9e88336-9719-4f43-afc9-b0e6c7d72b6f"
		fingerprint = "5c8c98b250252d178c8dbad60bf398489d9396968e33b3e004219a4f323eeed8"
		creation_date = "2022-03-22"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.OnlyLogger"
		reference_sample = "69876ee4d89ba68ee86f1a4eaf0a7cb51a012752e14c952a177cd5ffd8190986"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows.Trojan.OnlyLogger"
		filetype = "executable"

	strings:
		$a1 = "C:\\Users\\Ddani\\source\\repos\\onlyLogger\\Release\\onlyLogger.pdb" ascii fullword
		$b1 = "iplogger.org" ascii fullword
		$b2 = "NOT elevated" ascii fullword
		$b3 = "WinHttpSendRequest" ascii fullword

	condition:
		1 of ($a*) or all of ($b*)
}
