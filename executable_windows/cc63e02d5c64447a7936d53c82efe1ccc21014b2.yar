rule INDICATOR_TOOL_DWAgentLIB
{
	meta:
		author = "ditekSHen"
		description = "Detect DWAgent Remote Administration Tool library"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DWAgentLib" fullword wide
		$s2 = "PYTHONHOME" fullword wide
		$s3 = "isTaskRunning" fullword ascii
		$s4 = "isUserInAdminGroup" fullword ascii
		$s5 = "setFilePermissionEveryone" fullword ascii
		$s6 = "startProcessInActiveConsole" fullword ascii
		$s7 = "taskKill" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
