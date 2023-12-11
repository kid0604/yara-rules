import "pe"

rule MALWARE_Win_PELoader_RunPE
{
	meta:
		author = "ditekSHen"
		description = "Detects PE loader / injector. Observed Gorgon TTPs"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "commandLine'" fullword ascii
		$s2 = "RunPe.dll" fullword ascii
		$s3 = "HandleRun" fullword ascii
		$s4 = "inheritHandles" fullword ascii
		$s5 = "BlockCopy" fullword ascii
		$s6 = "WriteProcessMemory" fullword ascii
		$s7 = "startupInfo" fullword ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}
