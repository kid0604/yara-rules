rule INDICATOR_TOOL_PET_SharpSphere
{
	meta:
		author = "ditekSHen"
		description = "Detects SharpSphere red teamers tool to interact with the guest operating systems of virtual machines managed by vCenter"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "get_virtualExecUsage" fullword ascii
		$s2 = "Command to execute" fullword ascii
		$s3 = "<guestusername>k__" ascii
		$s4 = ".VirtualMachineDeviceRuntimeInfoVirtualEthernetCardRuntimeState" ascii
		$s5 = "datastoreUrl" ascii
		$s6 = "SharpSphere.vSphere." ascii
		$s7 = "HelpText+vCenter SDK URL, i.e. https://127.0.0.1/sdk" ascii
		$s8 = "[x] Execution finished, attempting to retrieve the results" fullword wide
		$s9 = "C:\\Windows\\System32\\cmd.exe" fullword wide
		$s10 = "C:\\Users\\Public\\" fullword wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
