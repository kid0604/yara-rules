rule TA459_Malware_May17_2
{
	meta:
		description = "Detects TA459 related malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/RLf9qU"
		date = "2017-05-31"
		hash1 = "4601133e94c4bc74916a9d96a5bc27cc3125cdc0be7225b2c7d4047f8506b3aa"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Mcutil.dll" fullword ascii
		$a2 = "mcut.exe" fullword ascii
		$s1 = "Software\\WinRAR SFX" fullword ascii
		$s2 = "AYou may need to run this self-extracting archive as administrator" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and all of ($a*) and 1 of ($s*))
}
