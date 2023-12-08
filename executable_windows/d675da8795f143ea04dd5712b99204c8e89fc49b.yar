import "math"
import "pe"

rule StoneDrill_Malware_2
{
	meta:
		description = "Detects malware from StoneDrill threat report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		date = "2017-03-07"
		hash1 = "69530d78c86031ce32583c6800f5ffc629acacb18aac4c8bb5b0e915fc4cc4db"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd /c WMIC Process Call Create \"C:\\Windows\\System32\\Wscript.exe //NOLOGO " fullword wide
		$s2 = "C:\\ProgramData\\InternetExplorer" fullword wide
		$s3 = "WshShell.CopyFile \"" fullword wide
		$s4 = "Abd891.tmp" fullword wide
		$s5 = "Set WshShell = Nothing" fullword wide
		$s6 = "AaCcdDeFfGhiKLlMmnNoOpPrRsSTtUuVvwWxyZz32" fullword ascii
		$s7 = "\\FileInfo.txt" wide
		$x1 = "C-PDI-C-Cpy-T.vbs" fullword wide
		$x2 = "C-Dlt-C-Org-T.vbs" fullword wide
		$x3 = "C-PDC-C-Cpy-T.vbs" fullword wide
		$x4 = "AC-PDC-C-Cpy-T.vbs" fullword wide
		$x5 = "C-Dlt-C-Trsh-T.tmp" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and (1 of ($x*) or 3 of ($s*))) or 5 of them
}
