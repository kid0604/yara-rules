rule Windows_Trojan_IcedID_08530e24
{
	meta:
		author = "Elastic Security"
		id = "08530e24-5b84-40a4-bc5c-ead74762faf8"
		fingerprint = "f2b5768b87eec7c1c9730cc99364cc90e87fd9201bf374418ad008fd70d321af"
		creation_date = "2021-03-21"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.IcedID"
		reference_sample = "31db92c7920e82e49a968220480e9f130dea9b386083b78a79985b554ecdc6e4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan IcedID variant 08530e24"
		filetype = "executable"

	strings:
		$a1 = "c:\\ProgramData\\" ascii fullword
		$a2 = "loader_dll_64.dll" ascii fullword
		$a3 = "aws.amazon.com" wide fullword
		$a4 = "Cookie: __gads=" wide fullword
		$b1 = "LookupAccountNameW" ascii fullword
		$b2 = "GetUserNameA" ascii fullword
		$b3 = "; _gat=" wide fullword
		$b4 = "; _ga=" wide fullword
		$b5 = "; _u=" wide fullword
		$b6 = "; __io=" wide fullword
		$b7 = "; _gid=" wide fullword
		$b8 = "%s%u" wide fullword
		$b9 = "i\\|9*" ascii fullword
		$b10 = "WinHttpSetStatusCallback" ascii fullword

	condition:
		all of ($a*) and 5 of ($b*)
}
