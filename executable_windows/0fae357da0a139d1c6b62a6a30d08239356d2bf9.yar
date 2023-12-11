rule INDICATOR_TOOL_PET_SharpStrike
{
	meta:
		author = "ditekSHen"
		description = "Detect SharpStrike post-exploitation tool written in C# that uses either CIM or WMI to query remote systems"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "SharpStrike v" wide
		$x2 = "[*] Agent is busy" wide
		$x3 = "SharpStrike_Fody" fullword ascii
		$s1 = "ServiceLayer.CIM" fullword ascii
		$s2 = "Models.CIM" fullword ascii
		$s3 = "<HandleCommand>b__" ascii
		$s4 = "MemoryStream" fullword ascii
		$s5 = "GetCommands" fullword ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($x*) or all of ($s*))
}
