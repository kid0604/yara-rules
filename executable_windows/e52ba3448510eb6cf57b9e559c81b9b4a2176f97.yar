rule Windows_Trojan_Vidar_114258d5
{
	meta:
		author = "Elastic Security"
		id = "114258d5-f05e-46ac-914b-1a7f338ccf58"
		fingerprint = "9b4f7619e15398fcafc622af821907e4cf52964c55f6a447327738af26769934"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Vidar"
		reference_sample = "34c0cb6eaf2171d3ab9934fe3f962e4e5f5e8528c325abfe464d3c02e5f939ec"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Vidar"
		filetype = "executable"

	strings:
		$a1 = "BinanceChainWallet" fullword
		$a2 = "*wallet*.dat" fullword
		$a3 = "SOFTWARE\\monero-project\\monero-core" fullword
		$b1 = "CC\\%s_%s.txt" fullword
		$b2 = "History\\%s_%s.txt" fullword
		$b3 = "Autofill\\%s_%s.txt" fullword

	condition:
		1 of ($a*) and 1 of ($b*)
}
