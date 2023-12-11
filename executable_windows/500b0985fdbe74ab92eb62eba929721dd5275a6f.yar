import "pe"

rule APT_FIN7_EXE_Sample_Aug18_8
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "d8bda53d7f2f1e4e442a0e1c30a20d6b0ac9c6880947f5dd36f78e4378b20c5c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "GetL3st3rr" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and all of them
}
