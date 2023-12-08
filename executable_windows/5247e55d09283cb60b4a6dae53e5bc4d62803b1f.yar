rule Windows_Ransomware_Clop_e04959b5 : beta
{
	meta:
		author = "Elastic Security"
		id = "e04959b5-f3da-428d-8b56-8a9817fdebe0"
		fingerprint = "7367b90772ce6db0d639835a0a54a994ef8ed351b6dadff42517ed5fbc3d0d1a"
		creation_date = "2020-05-03"
		last_modified = "2021-08-23"
		description = "Identifies CLOP ransomware in unpacked state"
		threat_name = "Windows.Ransomware.Clop"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "-%s\\CIopReadMe.txt" wide fullword
		$a2 = "CIopReadMe.txt" wide fullword
		$a3 = "%s-CIop^_" wide fullword
		$a4 = "%s%s.CIop" wide fullword
		$a5 = "BestChangeT0p^_-666" ascii fullword
		$a6 = ".CIop" wide fullword
		$a7 = "A%s\\ClopReadMe.txt" wide fullword
		$a8 = "%s%s.Clop" wide fullword
		$a9 = "CLOP#666" wide fullword
		$a10 = "MoneyP#666" wide fullword

	condition:
		1 of ($a*)
}
