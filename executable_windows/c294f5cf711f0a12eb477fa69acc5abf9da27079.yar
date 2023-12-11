rule Stuxnet_Malware_2
{
	meta:
		description = "Stuxnet Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "63e6b8136058d7a06dfff4034b4ab17a261cdf398e63868a601f77ddd1b32802"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\SystemRoot\\System32\\hal.dll" wide
		$s2 = "http://www.jmicron.co.tw0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <70KB and all of them
}
