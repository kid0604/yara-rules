import "pe"

rule APT_GreyEnergy_Malware_Oct18_2
{
	meta:
		description = "Detects samples from Grey Energy report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
		date = "2018-10-17"
		hash1 = "c6a54912f77a39c8f909a66a940350dcd8474c7a1d0e215a878349f1b038c58a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WioGLtonuaptWmrnttfepgetneemVsnygnV" fullword ascii
		$s2 = "PnSenariopoeKerGEtxrcy" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 2 of them
}
