import "pe"

rule MALWARE_Win_RedLineDropperAHK
{
	meta:
		author = "ditekSHen"
		description = "Detects AutoIt/AutoHotKey executables dropping RedLine infostealer"
		clamav_sig = "MALWARE.Win.Trojan.RedLineDropper-AHK"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".SetRequestHeader(\"User-Agent\",\" ( \" OSName \" | \" bit \" | \" CPUNAme \"\"" ascii
		$s2 = ":= \" | Windows Defender\"" ascii
		$s3 = "WindowSpy.ahk" wide
		$s4 = ">AUTOHOTKEY SCRIPT<" fullword wide

	condition:
		uint16(0)==0x5a4d and all of them
}
