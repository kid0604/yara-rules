import "pe"

rule CN_Hacktool_1433_Scanner_alt_1
{
	meta:
		description = "Detects a chinese MSSQL scanner"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 40
		date = "12.10.2014"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "del Weak1.txt" ascii fullword
		$s3 = "del Attack.txt" ascii fullword
		$s4 = "del /s /Q C:\\Windows\\system32\\doors\\" ascii
		$s5 = "!&start iexplore http://www.crsky.com/soft/4818.html)" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of ($s*)
}
