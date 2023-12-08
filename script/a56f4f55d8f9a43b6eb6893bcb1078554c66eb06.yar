rule Tzddos_DDoS_Tool_CN
{
	meta:
		description = "Disclosed hacktool set - file tzddos"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d4c517eda5458247edae59309453e0ae7d812f8e"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "for /f %%a in (host.txt) do (" fullword ascii
		$s1 = "for /f \"eol=S tokens=1 delims= \" %%i in (s2.txt) do echo %%i>>host.txt" fullword ascii
		$s2 = "del host.txt /q" fullword ascii
		$s3 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
		$s4 = "start Http.exe %%a %http%" fullword ascii
		$s5 = "for /f \"eol=P tokens=1 delims= \" %%i in (s1.txt) do echo %%i>>s2.txt" fullword ascii
		$s6 = "del Result.txt s2.txt s1.txt " fullword ascii

	condition:
		all of them
}
