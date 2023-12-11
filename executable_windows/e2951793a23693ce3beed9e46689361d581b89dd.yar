rule INDICATOR_TOOL_REM_IntelliAdmin
{
	meta:
		author = "ditekSHen"
		description = "Detects commerical IntelliAdmin remote tool"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb1 = "\\Network Administrator" ascii
		$pdb2 = "\\Binaries\\Plugins\\Tools\\RPCService.pdb" ascii
		$s1 = "CIntelliAdminRPC" fullword wide
		$s2 = "IntelliAdmin RPC Service" fullword wide
		$s3 = "IntelliAdmin Remote Execute v" ascii
		$s4 = "IntelliAdminRPC" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($pdb*) or 2 of ($s*))
}
