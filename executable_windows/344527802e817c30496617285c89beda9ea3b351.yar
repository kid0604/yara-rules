rule APT_Proxy_Malware_Packed_dev
{
	meta:
		author = "FRoth"
		date = "2014-11-10"
		description = "APT Malware - Proxy"
		hash = "6b6a86ceeab64a6cb273debfa82aec58"
		score = 50
		os = "windows"
		filetype = "executable"

	strings:
		$string0 = "PECompact2" fullword
		$string1 = "[LordPE]"
		$string2 = "steam_ker.dll"

	condition:
		all of them
}
