rule FiveEyes_QUERTY_Malwaresig_20121_dll
{
	meta:
		description = "FiveEyes QUERTY Malware - file 20121.dll.bin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "89504d91c5539a366e153894c1bc17277116342b"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "WarriorPride\\production2.0\\package\\E_Wzowski" ascii
		$s1 = "20121.dll" fullword ascii

	condition:
		all of them
}
