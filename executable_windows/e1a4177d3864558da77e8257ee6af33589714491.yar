import "pe"

rule MALWARE_Win_ParallaxRAT
{
	meta:
		author = "ditekSHen"
		description = "Detects ParallaxRAT"
		clamav_sig = "MALWARE.Win.Trojan.ParallaxRAT"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[Clipboard End]" fullword wide
		$s2 = "[Ctrl +" fullword wide
		$s3 = "[Alt +" fullword wide
		$s4 = "Clipboard Start" wide
		$s5 = "(Wscript.ScriptFullName)" wide
		$s6 = "CSDVersion" fullword ascii
		$s7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" fullword ascii
		$x1 = { 2e 65 78 65 00 00 84 00 00 4d 5a 90 00 }
		$x2 = "This program cannot be run in DOS mode" ascii

	condition:
		(( uint16(0)==0x5a4d and all of ($s*)) or all of them )
}
