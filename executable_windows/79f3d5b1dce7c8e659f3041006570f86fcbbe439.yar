rule INDICATOR_TOOL_ENUM_SharpShares
{
	meta:
		author = "ditekSHen"
		description = "Detects SharpShares multithreaded C# .NET Assembly to enumerate accessible network shares in a domain"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SharpShares." ascii wide
		$s2 = "GetComputerShares" fullword ascii
		$s3 = "userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2" wide
		$s4 = "GetAllShares" fullword ascii
		$s5 = "stealth:" wide
		$s6 = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*))" fullword wide
		$s7 = /\/targets|ldap|threads/ wide
		$s8 = "entriesread" fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
