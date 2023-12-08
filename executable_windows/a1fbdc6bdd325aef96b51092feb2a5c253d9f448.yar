rule INDICATOR_TOOL_LTM_SharpExec
{
	meta:
		author = "ditekSHen"
		description = "Detects SharpExec lateral movement tool"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "fileUploaded" fullword ascii
		$s2 = "$7fbad126-e21c-4c4e-a9f0-613fcf585a71" fullword ascii
		$s3 = "DESKTOP_HOOKCONTROL" fullword ascii
		$s4 = /WINSTA_(ACCESSCLIPBOARD|WINSTA_ALL_ACCESS)/ fullword ascii
		$s5 = /NETBIND(ADD|DISABLE|ENABLE|REMOVE)/ fullword ascii
		$s6 = /SERVICE_(ALL_ACCESS|WIN32_OWN_PROCESS|INTERROGATE)/ fullword ascii
		$s7 = /(Sharp|PS|smb)Exec/ fullword ascii
		$s8 = "lpszPassword" fullword ascii
		$s9 = "lpszDomain" fullword ascii
		$s10 = "wmiexec" fullword ascii
		$s11 = "\\C$\\__LegitFile" wide
		$s12 = "LOGON32_LOGON_NEW_CREDENTIALS" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 9 of them ) or ( all of them )
}
