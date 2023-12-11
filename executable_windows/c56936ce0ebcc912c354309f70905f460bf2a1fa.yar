rule Windows_Trojan_CyberGate_517aac7d
{
	meta:
		author = "Elastic Security"
		id = "517aac7d-2737-4917-9aa1-c0bd1c3e9801"
		fingerprint = "3d998bda8e56de6fd6267abdacffece8bcf1c62c2e06540a54244dc6ea816825"
		creation_date = "2022-02-28"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.CyberGate"
		reference_sample = "07b8f25e7b536f5b6f686c12d04edc37e11347c8acd5c53f98a174723078c365"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan CyberGate"
		filetype = "executable"

	strings:
		$a1 = "IELOGIN.abc" ascii fullword
		$a2 = "xxxyyyzzz.dat" ascii fullword
		$a3 = "_x_X_PASSWORDLIST_X_x_" ascii fullword
		$a4 = "L$_RasDefaultCredentials#0" ascii fullword
		$a5 = "\\signons1.txt" ascii fullword

	condition:
		all of them
}
