rule INDICATOR_TOOL_ANT_SharpEDRChecker
{
	meta:
		author = "ditekSHen"
		description = "Detect SharpEDRChecke, C# Implementation of Invoke-EDRChecker"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb1 = "\\SharpEDRChecker.pdb" fullword ascii
		$x1 = "EDRData" fullword ascii
		$x2 = "bytesNeeded" fullword ascii
		$x3 = /\] Checking (Directories|drivers|processes|modules|Registry|Services) \[/ wide
		$s1 = "CheckService" fullword ascii
		$s2 = "CheckModule" fullword ascii
		$s3 = "PrivCheck" fullword ascii
		$s4 = "ServiceChecker" fullword ascii
		$s5 = "PrivilegeChecker" fullword ascii
		$s6 = "FileChecker" fullword ascii
		$s7 = "DriverChecker" fullword ascii
		$s8 = "ProcessChecker" fullword ascii
		$s9 = "DirectoryChecker" fullword ascii
		$s10 = "RegistryChecker" fullword ascii
		$s11 = "CheckDriver" fullword ascii
		$s12 = "CheckServices" fullword ascii
		$s13 = "CheckDirectories" fullword ascii
		$s14 = "CheckCurrentProcessModules" fullword ascii
		$s15 = "CheckProcesses" fullword ascii
		$s16 = "CheckDrivers" fullword ascii
		$s17 = "CheckProcess" fullword ascii
		$s18 = "CheckSubDirectory" fullword ascii
		$s19 = "CheckDirectory" fullword ascii
		$s20 = "CheckRegistry" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($x*) or 10 of ($s*) or (1 of ($pdb*) and (1 of ($x*) or 2 of ($s*))) or (#x3>4 and 2 of them ))
}
