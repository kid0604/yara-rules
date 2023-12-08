import "pe"

rule Scieron
{
	meta:
		author = "Symantec Security Response"
		ref = "http://www.symantec.com/connect/tr/blogs/scarab-attackers-took-aim-select-russian-targets-2012"
		date = "22.01.15"
		description = "Yara rule for detecting Scarab attackers targeting Russian victims in 2012"
		os = "windows"
		filetype = "executable"

	strings:
		$code1 = {66 83 F? 2C 74 0C 66 83 F? 3B 74 06 66 83 F? 7C 75 05}
		$code2 = {83 F? 09 0F 87 ?? 0? 00 00 FF 24}
		$str1 = "IP_PADDING_DATA" wide ascii
		$str2 = "PORT_NUM" wide ascii

	condition:
		all of them
}
