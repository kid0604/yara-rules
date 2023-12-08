rule Windows_Trojan_Trickbot_618b27d2
{
	meta:
		author = "Elastic Security"
		id = "618b27d2-22ad-4542-86ed-7148f17971da"
		fingerprint = "df4336e5cbca495dac4fe110bd7a727e91bb3d465f76d3f3796078332c13633c"
		creation_date = "2021-03-30"
		last_modified = "2021-08-23"
		description = "Targets Outlook.dll module containing functionality used to retrieve Outlook data"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "d3ec8f4a46b21fb189fc3d58f3d87bf9897653ecdf90b7952dcc71f3b4023b4e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "OutlookX32.dll" ascii fullword
		$a2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" wide fullword
		$a3 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook" wide fullword
		$a4 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook" wide fullword
		$a5 = "OutlookX32" ascii fullword
		$a6 = " Port:" wide fullword
		$a7 = " User:" wide fullword
		$a8 = " Pass:" wide fullword
		$a9 = "String$" ascii fullword
		$a10 = "outlookDecrU" ascii fullword
		$a11 = "Cannot Decrypt" ascii fullword
		$a12 = " Mail:" wide fullword
		$a13 = " Serv:" wide fullword
		$a14 = ",outlookDecr" ascii fullword
		$a15 = "CryptApi" ascii fullword

	condition:
		5 of ($a*)
}
