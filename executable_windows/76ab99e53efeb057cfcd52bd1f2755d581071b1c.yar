import "pe"

rule MAL_RANSOM_LockBit_Indicators_Feb24
{
	meta:
		description = "Detects Lockbit ransomware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
		author = "Florian Roth"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		date = "2024-02-23"
		score = 75
		hash1 = "a50d9954c0a50e5804065a8165b18571048160200249766bfa2f75d03c8cb6d0"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { 76 c1 95 8b 18 00 93 56 bf 2b 88 71 4c 34 af b1 a5 e9 77 46 c3 13 }
		$op2 = { e0 02 10 f7 ac 75 0e 18 1b c2 c1 98 ac 46 }
		$op3 = { 8b c6 ab 53 ff 15 e4 57 42 00 ff 45 fc eb 92 ff 75 f8 ff 15 f4 57 42 00 }

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="914685b69f2ac2ff61b6b0f1883a054d" or 2 of them ) or all of them
}
