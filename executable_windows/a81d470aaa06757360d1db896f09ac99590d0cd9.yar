rule pth_addadmin
{
	meta:
		description = "19438 - file pth_addadmin.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
		date = "2023-10-29"
		hash1 = "3bee705c062227dcb2d109bf62ab043c68ba3fb53b1ce679dc138273ba884b08"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "@[+] Command executed" fullword ascii
		$s2 = "33333337333333" ascii
		$s3 = "@Command executed with service" fullword ascii
		$s4 = "SMBExecCommandLengthBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_56" fullword ascii
		$s5 = "SMBExecCommandBytes__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_55" fullword ascii
		$s6 = "SMBExecCommand__OOZOOZ85sersZ65dministratorZOnimbleZpkgsZ83776669xec4549O48O48Z83776669xecZ69xec83tages_54" fullword ascii
		$s7 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2.nim.c" fullword ascii
		$s8 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv2Helper.nim.c" fullword ascii
		$s9 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSCM.nim.c" fullword ascii
		$s10 = "@The user does not have Service Control Manager write privilege on the target" fullword ascii
		$s11 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sExecStages.nim.c" fullword ascii
		$s12 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sRPC.nim.c" fullword ascii
		$s13 = "@Trying to execute command on the target" fullword ascii
		$s14 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sNTLM.nim.c" fullword ascii
		$s15 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sHelpUtil.nim.c" fullword ascii
		$s16 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec.nim.c" fullword ascii
		$s17 = "@The user has Service Control Manager write privilege on the target" fullword ascii
		$s18 = "@m..@s..@sUsers@sAdministrator@s.nimble@spkgs@sSMBExec-1.0.0@sSMBExec@sSMBv1.nim.c" fullword ascii
		$s19 = "@Bcrypt.dll" fullword ascii
		$s20 = "@Service creation failed on target" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 8 of them
}
