import "pe"

rule MALWARE_Win_Renamer
{
	meta:
		author = "ditekSHen"
		description = "Detects Renamer/Tainp variants"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "shell\\open\\command=" fullword wide
		$s2 = "icon=%SystemRoot%\\system32\\SHELL32.dll,4" fullword wide
		$s3 = "DropTarget" ascii
		$s4 = "C:\\Windows\\Paint" fullword wide
		$s5 = "hold.inf" fullword wide
		$s6 = "Dropped" ascii

	condition:
		uint16(0)==0x5a4d and all of ($s*) or (4 of ($s*) and for any directory in pe.data_directories : (directory.virtual_address!=0 and directory.size==0))
}
