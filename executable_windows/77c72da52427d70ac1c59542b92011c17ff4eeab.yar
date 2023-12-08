import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_Anti_OldCopyPaste
{
	meta:
		author = "ditekSHen"
		description = "Detects executables potentially checking for WinJail sandbox window"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "This file can't run into Virtual Machines" wide
		$s2 = "This file can't run into Sandboxies" wide
		$s3 = "This file can't run into RDP Servers" wide
		$s4 = "Run without emulation" wide
		$s5 = "Run using valid operating system" wide
		$v1 = "SbieDll.dll" fullword wide
		$v2 = "USER" fullword wide
		$v3 = "SANDBOX" fullword wide
		$v4 = "VIRUS" fullword wide
		$v5 = "MALWARE" fullword wide
		$v6 = "SCHMIDTI" fullword wide
		$v7 = "CURRENTUSER" fullword wide

	condition:
		uint16(0)==0x5a4d and (3 of ($s*) or all of ($v*))
}
