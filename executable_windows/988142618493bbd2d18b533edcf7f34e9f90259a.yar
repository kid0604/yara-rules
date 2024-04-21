rule __case_5295_zero
{
	meta:
		description = "5295 - file zero.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-12"
		hash1 = "3a8b7c1fe9bd9451c0a51e4122605efc98e7e4e13ed117139a13e4749e211ed0"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "powershell.exe -c Reset-ComputerMachinePassword" fullword wide
		$s2 = "COMMAND - command that will be executed on domain controller. should be surrounded by quotes" fullword ascii
		$s3 = "ZERO.EXE IP DC DOMAIN ADMIN_USERNAME [-c] COMMAND :" fullword ascii
		$s4 = "-c - optional, use it when command is not binary executable itself" fullword ascii
		$s5 = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii
		$s6 = "C:\\p\\Release\\zero.pdb" fullword ascii
		$s7 = "+command executed" fullword ascii
		$s8 = "COMMAND - %ws" fullword ascii
		$s9 = "rpc_drsr_ProcessGetNCChangesReply" fullword wide
		$s10 = "ZERO.EXE -test IP DC" fullword ascii
		$s11 = "to test if the target is vulnurable only" fullword ascii
		$s12 = "IP - ip address of domain controller" fullword ascii
		$s13 = "ADMIN_USERNAME - %ws" fullword ascii
		$s14 = "error while parsing commandline. no command is found" fullword ascii
		$s15 = "rpcbindingsetauthinfo fail" fullword ascii
		$s16 = "x** SAM ACCOUNT **" fullword wide
		$s17 = "%COMSPEC% /C " fullword wide
		$s18 = "EXECUTED SUCCESSFULLY" fullword ascii
		$s19 = "TARGET IS VULNURABLE" fullword ascii
		$s20 = "have no admin rights on target, exiting" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and 1 of ($x*) and 4 of them
}
