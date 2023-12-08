rule ICMLuaUtil_UACMe_M41 : uac_bypass
{
	meta:
		description = "A Yara rule for UACMe Method 41 -> ICMLuaUtil Elevated COM interface"
		author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
		date = "2021-01-19"
		TLP = "WHITE"
		reference = "https://github.com/hfiref0x/UACME"
		os = "windows"
		filetype = "executable"

	strings:
		$elevation = "Elevation:Administrator!new:" wide ascii
		$clsid_CMSTPLUA = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide ascii
		$iid_ICMLuaUtil = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" wide ascii
		$clsid_bytes = {95 D1 16 0A 47 6F 64 49 92 87 9F 4B AB 6D 98 27}
		$iid_bytes = {74 6D DD 6E 07 C0 75 4E B7 6A E5 74 09 95 E2 4C}

	condition:
		uint16(0)==0x5a4d and (($elevation and $clsid_CMSTPLUA and $iid_ICMLuaUtil) or ($clsid_bytes and $iid_bytes))
}
