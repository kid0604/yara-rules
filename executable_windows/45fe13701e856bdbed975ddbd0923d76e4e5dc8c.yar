import "pe"

rule disable_dep
{
	meta:
		author = "x0r"
		description = "Bypass DEP"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = "EnableExecuteProtectionSupport"
		$c2 = "NtSetInformationProcess"
		$c3 = "VirtualProctectEx"
		$c4 = "SetProcessDEPPolicy"
		$c5 = "ZwProtectVirtualMemory"

	condition:
		any of them
}
