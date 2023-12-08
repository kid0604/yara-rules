import "pe"

rule TopHat_Malware_Jan18_1
{
	meta:
		description = "Detects malware from TopHat campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-the-tophat-campaign-attacks-within-the-middle-east-region-using-popular-third-party-services/#appendix"
		date = "2018-01-29"
		hash1 = "5c0b253966befd57f4d22548f01116ffa367d027f162514c1b043a747bead596"
		hash2 = "1f9bca1d5ce5d14d478d32f105b3ab5d15e1c520bde5dfca22324262e84d4eaf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WINMGMTS:\\\\.\\ROOT\\CIMV2" fullword ascii
		$s2 = "UENCRYPTION" fullword ascii
		$s3 = "TEXPORTAPIS" fullword ascii
		$s4 = "tcustommemorystream" fullword ascii
		$s5 = "tmemorystream" fullword ascii
		$s6 = "ExtrasNoteCONSOLEemb" fullword ascii
		$s7 = "DIALOG INCLUDE" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (pe.imphash()=="c221006b240b1c993217bd61e5ee31b6" or 6 of them )
}
