import "pe"

rule APT_FIN7_EXE_Sample_Aug18_1
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "7f16cbe7aa1fbc5b8a95f9d123f45b7e3da144cb88db6e1da3eca38cf88660cb"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Manche Enterprises Limited0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <800KB and 1 of them
}
