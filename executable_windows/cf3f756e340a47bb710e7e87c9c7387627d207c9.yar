rule Mal_PotPlayer_DLL : dll
{
	meta:
		description = "Detects a malicious PotPlayer.dll"
		author = "Florian Roth"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 70
		hash1 = "705409bc11fb45fa3c4e2fa9dd35af7d4613e52a713d9c6ea6bc4baff49aa74a"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C:\\Users\\john\\Desktop\\PotPlayer\\Release\\PotPlayer.pdb" fullword ascii
		$s3 = "PotPlayer.dll" fullword ascii
		$s4 = "\\update.dat" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and $x1 or all of ($s*)
}
