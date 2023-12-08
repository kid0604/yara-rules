rule SUSP_LNK_SuspiciousCommands
{
	meta:
		description = "Detects LNK file with suspicious content"
		author = "Florian Roth (Nextron Systems)"
		date = "2018-09-18"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = " -decode " ascii wide
		$s2 = " -enc " ascii wide
		$s3 = " -w hidden " ascii wide
		$s4 = " -ep bypass " ascii wide
		$s5 = " -noni " ascii nocase wide
		$s7 = " -noprofile " ascii wide
		$s8 = ".DownloadString(" ascii wide
		$s9 = ".DownloadFile(" ascii wide
		$s10 = "IEX(" ascii wide
		$s11 = "iex(" ascii wide
		$s12 = "WScript.shell" ascii wide fullword nocase
		$s13 = " -nop " ascii wide
		$s14 = "&tasklist>"
		$s15 = "setlocal EnableExtensions DisableDelayedExpansion"
		$s16 = "echo^ set^"
		$s17 = "del /f /q "
		$s18 = " echo | start "
		$s19 = "&& echo "
		$s20 = "&&set "
		$s21 = "%&&@echo off "

	condition:
		uint16(0)==0x004c and 1 of them
}
