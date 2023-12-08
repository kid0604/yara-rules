rule Empire_Invoke_SMBAutoBrute
{
	meta:
		description = "Detects Empire component - file Invoke-SMBAutoBrute.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "7950f8abdd8ee09ed168137ef5380047d9d767a7172316070acc33b662f812b2"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "[*] PDC: LAB-2008-DC1.lab.com" fullword ascii
		$s2 = "$attempts = Get-UserBadPwdCount $userid $dcs" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <30KB and 1 of them ) or all of them
}
