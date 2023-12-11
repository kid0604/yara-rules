rule Hacktools_CN_Scan_BAT
{
	meta:
		description = "Disclosed hacktool set - file scan.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "6517d7c245f1300e42f7354b0fe5d9666e5ce52a"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "for /f %%a in (host.txt) do (" fullword ascii
		$s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
		$s2 = "del host.txt /q" fullword ascii
		$s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s4 = "start Http.exe %%a %http%" fullword ascii
		$s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii

	condition:
		5 of them
}
