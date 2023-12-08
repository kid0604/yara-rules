import "pe"

rule APT_FIN7_EXE_Sample_Aug18_10
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "8cc02b721683f8b880c8d086ed055006dcf6155a6cd19435f74dd9296b74f5fc"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = { 00 4C 00 65 00 67 00 61 00 6C 00 43 00 6F 00 70
               00 79 00 72 00 69 00 67 00 68 00 74 00 00 00 43
               00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74
               00 20 00 31 00 20 00 2D 00 20 00 31 00 39 00 }

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 1 of them
}
