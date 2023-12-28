rule Lazarus_VSingle_github
{
	meta:
		description = "VSingle using GitHub in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash = "199ba618efc6af9280c5abd86c09cdf2d475c09c8c7ffc393a35c3d70277aed1"
		hash = "2eb16dbc1097a590f07787ab285a013f5fe235287cb4fb948d4f9cce9efa5dbc"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "Arcan3" ascii wide fullword
		$str2 = "Wr0te" ascii wide fullword
		$str3 = "luxuryboy" ascii wide fullword
		$str4 = "pnpgather" ascii wide fullword
		$str5 = "happyv1m" ascii wide fullword
		$str6 = "laz3rpik" ascii wide fullword
		$str7 = "d0ta" ascii wide fullword
		$str8 = "Dronek" ascii wide fullword
		$str9 = "Panda3" ascii wide fullword
		$str10 = "cpsponso" ascii wide fullword
		$str11 = "ggo0dlluck" ascii wide fullword
		$str12 = "gar3ia" ascii wide fullword
		$str13 = "wo0d" ascii wide fullword
		$str14 = "tr3e" ascii wide fullword
		$str15 = "l0ve" ascii wide fullword
		$str16 = "v0siej" ascii wide fullword
		$str17 = "e0vvsje" ascii wide fullword
		$str18 = "polaris" ascii wide fullword
		$str19 = "grav1ty" ascii wide fullword
		$str20 = "w1inter" ascii wide fullword

	condition:
		( uint32(0)==0x464C457F and 8 of ($str*)) or ( uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and 8 of ($str*))
}
