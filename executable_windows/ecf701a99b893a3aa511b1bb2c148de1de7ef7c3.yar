rule StormKitty_alt_4
{
	meta:
		author = "ditekSHen"
		description = "StormKitty infostealer payload"
		cape_type = "StormKitty Payload"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\ARTIKA\\Videos\\Chrome-Password-Recovery" ascii
		$x2 = "https://github.com/LimerBoy/StormKitty" fullword ascii
		$x3 = "StormKitty" fullword ascii
		$s1 = "GetBSSID" fullword ascii
		$s2 = "GetAntivirus" fullword ascii
		$s3 = "C:\\Users\\Public\\credentials.txt" fullword wide
		$s4 = "^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$" fullword wide
		$s5 = "BCrypt.BCryptGetProperty() (get size) failed with status code:{0}" fullword wide
		$s6 = "\"encrypted_key\":\"(.*?)\"" fullword wide
		$ww2 = "WorldWindClient" wide fullword nocase
		$ww3 = "WorldWindStealer" wide fullword nocase
		$ww4 = "*WorldWind Pro - Results:*" wide fullword nocase
		$ww5 = /WorldWind(\s)?Stealer/ ascii wide
		$prynt = /Prynt(\s)?Stealer/ ascii wide

	condition:
		uint16(0)==0x5a4d and ( not any of ($ww*) and not $prynt) and (2 of ($x*) or 5 of ($s*) or (3 of ($s*) and 1 of ($x*)))
}
