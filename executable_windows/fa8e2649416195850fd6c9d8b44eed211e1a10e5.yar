import "pe"

rule SunOrcal_Malware_Nov17_1
{
	meta:
		description = "Detects Reaver malware mentioned in PaloAltoNetworks report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/"
		date = "2017-11-11"
		hash1 = "cb7c0cf1750baaa11783e93369230ee666b9f3da7298e4d1bb9a07af6a439f2f"
		hash2 = "799139b5278dc2ac24279cc6c3db44f4ef0ea78ee7b721b0ace38fd8018c51ac"
		hash3 = "38ea33dab0ba2edd16ecd98cba161c550d1036b253c8666c4110d198948329fb"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "kQZ6l5t1kAlsjmBzsCZPrSpQn5tFrChLtTdsgTlOsClKt5pBsDdFrSVshnxMr6ZOpn9slndBsy1jq6lIr216rSNApn9P" fullword ascii
		$x2 = { 00 00 00 00 00 00 00 00 00 00 00 00 21 21 21 73
              79 73 74 65 6D 00 00 00 00 00 00 00 00 00 00 00 }
		$x3 = "!!!url!!!" fullword ascii
		$x4 = "h4NcbkdLrCpFpPQ=" fullword ascii
		$x5 = "GloablCryptNv1" fullword ascii
		$x6 = "Gloabl\\CryptNv1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 1 of them
}
