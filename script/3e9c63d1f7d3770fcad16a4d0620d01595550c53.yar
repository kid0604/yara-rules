rule Hacktools_CN_GOGOGO_Bat
{
	meta:
		description = "Disclosed hacktool set - file GOGOGO.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "4bd4f5b070acf7fe70460d7eefb3623366074bbd"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "for /f \"delims=\" %%x in (endend.txt) do call :lisoob %%x" fullword ascii
		$s1 = "http://www.tzddos.com/ -------------------------------------------->byebye.txt" fullword ascii
		$s2 = "ren %systemroot%\\system32\\drivers\\tcpip.sys tcpip.sys.bak" fullword ascii
		$s4 = "IF /I \"%wangle%\"==\"\" ( goto start ) else ( goto erromm )" fullword ascii
		$s5 = "copy *.tzddos scan.bat&del *.tzddos" fullword ascii
		$s6 = "del /f tcpip.sys" fullword ascii
		$s9 = "if /i \"%CB%\"==\"www.tzddos.com\" ( goto mmbat ) else ( goto wangle )" fullword ascii
		$s10 = "call scan.bat" fullword ascii
		$s12 = "IF /I \"%erromm%\"==\"\" ( goto start ) else ( goto zuihoujh )" fullword ascii
		$s13 = "IF /I \"%zuihoujh%\"==\"\" ( goto start ) else ( goto laji )" fullword ascii
		$s18 = "sc config LmHosts start= auto" fullword ascii
		$s19 = "copy tcpip.sys %systemroot%\\system32\\drivers\\tcpip.sys > nul" fullword ascii
		$s20 = "ren %systemroot%\\system32\\dllcache\\tcpip.sys tcpip.sys.bak" fullword ascii

	condition:
		3 of them
}
