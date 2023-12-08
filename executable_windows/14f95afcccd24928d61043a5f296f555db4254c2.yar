import "pe"

rule MALWARE_Win_IceID
{
	meta:
		author = "ditekSHen"
		description = "Detects IceID / Bokbot variants"
		os = "windows"
		filetype = "executable"

	strings:
		$n1 = "POST" fullword wide
		$n2 = "; _gat=" fullword wide
		$n3 = "; _ga=" fullword wide
		$n4 = "; _u=" fullword wide
		$n5 = "; __io=" fullword wide
		$n6 = "; _gid=" fullword wide
		$n7 = "Cookie: __gads=" fullword wide
		$s1 = "c:\\ProgramData" ascii
		$s2 = "loader_dll_64.dll" fullword ascii
		$s3 = "loader_dll_32.dll" fullword ascii
		$s4 = "/?id=%0.2X%0.8X%0.8X%s" ascii
		$s5 = "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.8X" ascii

	condition:
		uint16(0)==0x5a4d and (( all of ($n*) and 1 of ($s*)) or (3 of ($s*) and 1 of ($n*)))
}
