import "pe"

rule Greenbug_Malware_2
{
	meta:
		description = "Detects Backdoor from Greenbug Incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/urp4CD"
		date = "2017-01-25"
		hash1 = "6b28a43eda5b6f828a65574e3f08a6d00e0acf84cbb94aac5cec5cd448a4649d"
		hash2 = "21f5e60e9df6642dbbceca623ad59ad1778ea506b7932d75ea8db02230ce3685"
		hash3 = "319a001d09ee9d754e8789116bbb21a3c624c999dae9cf83fde90a3fbe67ee6c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "|||Command executed successfully" fullword ascii
		$x2 = "\\Release\\Bot Fresh.pdb" ascii
		$x3 = "C:\\ddd\\a1.txt" fullword wide
		$x4 = "Bots\\Bot5\\x64\\Release" ascii
		$x5 = "Bot5\\Release\\Ism.pdb" ascii
		$x6 = "Bot\\Release\\Ism.pdb" ascii
		$x7 = "\\Bot Fresh\\Release\\Bot" ascii
		$s1 = "/Home/SaveFile?commandId=CmdResult=" fullword wide
		$s2 = "raB3G:Sun:Sunday:Mon:Monday:Tue:Tuesday:Wed:Wednesday:Thu:Thursday:Fri:Friday:Sat:Saturday" fullword ascii
		$s3 = "Set-Cookie:\\b*{.+?}\\n" fullword wide
		$s4 = "SELECT * FROM AntiVirusProduct" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and (1 of ($x*) or 2 of them )) or (3 of them )
}
