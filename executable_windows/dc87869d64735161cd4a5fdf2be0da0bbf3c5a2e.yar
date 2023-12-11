import "pe"

rule CN_Hacktool_1433_Scanner_Comp2_alt_1
{
	meta:
		description = "Detects a chinese MSSQL scanner - component 2"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 40
		date = "12.10.2014"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "UUUMUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUMUUU" ascii fullword

	condition:
		uint16(0)==0x5a4d and all of ($s*)
}
