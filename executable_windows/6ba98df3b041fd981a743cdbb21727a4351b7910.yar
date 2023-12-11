rule APT_MAL_Win_DecRok : InkySquid
{
	meta:
		author = "threatintel@volexity.com"
		date = "2021-06-23"
		description = "The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload."
		hash = "6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855"
		license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		os = "windows"
		filetype = "executable"

	strings:
		$v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}
		$av1 = "Select * From AntiVirusProduct" wide
		$av2 = "root\\SecurityCenter2" wide
		$funcformat = { 25 30 32 78 [0-10] 43 72 65 61 74 65 54 68 72 65 61 64 }

	condition:
		all of them
}
