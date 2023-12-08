import "pe"

rule new_keyboy_header_codes
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the 2016 sample's header codes"
		date = "2016-08-28"
		md5 = "495adb1b9777002ecfe22aaf52fcee93"
		description = "Matches the 2016 sample's header codes"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "*l*" wide fullword
		$s2 = "*a*" wide fullword
		$s3 = "*s*" wide fullword
		$s4 = "*d*" wide fullword
		$s5 = "*f*" wide fullword
		$s6 = "*g*" wide fullword
		$s7 = "*h*" wide fullword

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <200KB and all of them
}
