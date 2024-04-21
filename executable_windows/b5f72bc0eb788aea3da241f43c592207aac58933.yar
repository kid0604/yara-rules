import "pe"

rule icedid_win_01
{
	meta:
		description = "Detects Icedid"
		author = "The DFIR Report"
		date = "15/05/2021"
		description = "Detects Icedid functionality. incl. credential access, OS cmds."
		sha1 = "3F06392AF1687BD0BF9DB2B8B73076CAB8B1CBBA"
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DllRegisterServer" wide ascii fullword
		$x1 = "passff.tar" wide ascii fullword
		$x2 = "vaultcli.dll" wide ascii fullword
		$x3 = "cookie.tar" wide ascii fullword
		$y1 = "powershell.exe" wide ascii fullword
		$y2 = "cmd.exe" wide ascii fullword

	condition:
		( uint16(0)==0x5a4d and int32 ( uint32(0x3c))==0x00004550 and filesize <500KB and $s1 and (2 of ($x*) and 2 of ($y*)))
}
