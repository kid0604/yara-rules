import "pe"

rule MALWARE_Win_BabylonRAT
{
	meta:
		author = "ditekSHen"
		description = "Detects BabylonRAT / CollectorStealer / ParadoxRAT"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Babylon RAT Client" wide nocase
		$x2 = "ParadoxRAT_Client" fullword ascii
		$s1 = "@ConfigsEx" fullword wide
		$s2 = "ClipBoard.txt" fullword wide
		$s3 = "[%02d/%02d/%d %02d:%02d:%02d] [%s] (%s):" fullword wide
		$s4 = "\\%Y %m %d - %I %M %p" fullword wide
		$s5 = "[%02d/%02d/%d %02d:%02d:%02d] (%s)" fullword wide
		$s6 = " c:\\Windows\\system32\\cmd.exe" fullword wide
		$s7 = "Update Failed [OpenProcess]" wide
		$s8 = "DoS Already Active..." fullword wide
		$s9 = "File Downloaded and Execut" wide
		$s10 = "LgDError33x98dGetProcAddress" fullword wide
		$s11 = "@SPYNET" fullword wide
		$s12 = "Recovery.Recovery" fullword wide
		$s13 = "GetChrome" fullword wide
		$s14 = "\\drivers\\etc\\HOSTS" fullword ascii
		$s15 = "plugin-container.exe" fullword ascii
		$s16 = "bss_server.usrRelay" fullword ascii
		$s17 = "sckRelay" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($x*) or (1 of ($x*) and 3 of ($s*)) or 8 of ($s*))
}
