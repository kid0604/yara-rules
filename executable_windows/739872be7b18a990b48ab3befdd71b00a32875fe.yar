import "pe"

rule ZxShell_Related_Malware_CN_Group_Jul17_1
{
	meta:
		description = "Detects a ZxShell related sample from a CN threat group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/cat-phishing/"
		date = "2017-07-08"
		hash1 = "ef56c2609bc1b90f3e04745890235e6052a4be94e35e38b6f69b64fb17a7064e"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "CMD.EXE /C NET USER GUEST /ACTIVE:yes && NET USER GUEST ++++++" ascii
		$x2 = "system\\cURRENTcONTROLSET\\sERVICES\\tERMSERVICE" fullword ascii
		$x3 = "\\secivreS\\teSlortnoCtnerruC\\METSYS" ascii
		$x4 = "system\\cURRENTCONTROLSET\\cONTROL\\tERMINAL sERVER" fullword ascii
		$x5 = "sOFTWARE\\mICROSOFT\\iNTERNET eXPLORER\\mAIN" fullword ascii
		$x6 = "eNABLEaDMINtsREMOTE" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 1 of them )
}
