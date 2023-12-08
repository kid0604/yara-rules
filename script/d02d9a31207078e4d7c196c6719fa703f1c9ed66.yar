rule CN_Honker_sig_3389_3389_3
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file 3389.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cfedec7bd327897694f83501d76063fe16b13450"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "echo \"fDenyTSConnections\"=dword:00000000>>3389.reg " fullword ascii
		$s2 = "echo \"PortNumber\"=dword:00000d3d>>3389.reg " fullword ascii
		$s3 = "echo [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server]>>" ascii

	condition:
		filesize <2KB and all of them
}
