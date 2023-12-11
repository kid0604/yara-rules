import "pe"

rule Microcin_Sample_5
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		date = "2017-09-26"
		hash1 = "b9c51397e79d5a5fd37647bc4e4ee63018ac3ab9d050b02190403eb717b1366e"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Sorry, you are not fortuante ^_^, Please try other password dictionary " fullword ascii
		$x2 = "DomCrack <IP> <UserName> <Password_Dic file path> <option>" fullword ascii
		$x3 = "The password is \"%s\"         Time: %d(s)" fullword ascii
		$x4 = "The password is \" %s \"         Time: %d(s)" fullword ascii
		$x5 = "No password found!" fullword ascii
		$x7 = "Can not found the Password Dictoonary file! " fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them ) or 2 of them
}
