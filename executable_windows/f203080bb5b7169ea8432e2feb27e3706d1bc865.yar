rule HKTL_RedMimicry_Agent
{
	meta:
		date = "2020-06-22"
		modified = "2023-01-06"
		author = "mirar@chaosmail.org"
		sharing = "tlp:white"
		description = "matches the RedMimicry agent executable and payload"
		reference = "https://redmimicry.com"
		os = "windows"
		filetype = "executable"

	strings:
		$reg0 = "HKEY_CURRENT_USER\\" ascii
		$reg1 = "HKEY_LOCAL_MACHINE\\" ascii
		$reg2 = "HKEY_CURRENT_CONFIG\\" ascii
		$reg3 = "HKEY_CLASSES_ROOT\\" ascii
		$cmd0 = "C:\\Windows\\System32\\cmd.exe" ascii fullword
		$lua0 = "client_recv" ascii fullword
		$lua1 = "client_send" ascii fullword
		$lua2 = "$LuaVersion: " ascii
		$sym0 = "VirtualAllocEx" wide fullword
		$sym1 = "kernel32.dll" wide fullword

	condition:
		all of them
}
