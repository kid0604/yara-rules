rule INDICATOR_TOOL_DWAgentSVC
{
	meta:
		author = "ditekSHen"
		description = "Detect DWAgent Remote Administration Tool service"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\native\\dwagupd.dll" wide
		$s2 = "\\native\\dwagsvc.exe\" run" wide
		$s3 = "CreateServiceW" fullword ascii
		$s4 = /dwagent\.(pid|start|stop)/ wide
		$s5 = "Check updating..." wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
