import "pe"

rule MAL_Trickbot_Oct19_4
{
	meta:
		description = "Detects Trickbot malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-10-02"
		hash1 = "25a4ae2a1ce6dbe7da4ba1e2559caa7ed080762cf52dba6c8b55450852135504"
		hash2 = "e92dd00b092b435420f0996e4f557023fe1436110a11f0f61fbb628b959aac99"
		hash3 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
		hash4 = "9ecc794ec77ce937e8c835d837ca7f0548ef695090543ed83a7adbc07da9f536"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "c:\\users\\user\\documents\\visual studio 2005\\projects\\adzxser\\release\\ADZXSER.pdb" fullword ascii
		$x2 = "http://root-hack.org" fullword ascii
		$x3 = "http://hax-studios.net" fullword ascii
		$x4 = "5OCFBBKCAZxWUE#$_SVRR[SQJ" fullword ascii
		$x5 = "G*\\AC:\\Users\\911\\Desktop\\cButtonBar\\cButtonBar\\ButtonBar.vbp" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <=2000KB and 1 of them
}
