import "pe"

rule APT_FIN7_EXE_Sample_Aug18_4
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "4b5405fc253ed3a89c770096a13d90648eac10a7fb12980e587f73483a07aa4c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "c:\\file.dat" fullword wide
		$s2 = "constructor or from DllMain." fullword ascii
		$s3 = "lineGetCallIDs" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and all of them
}
