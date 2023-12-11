import "pe"

rule Casper_Included_Strings_alt_1
{
	meta:
		description = "Casper French Espionage Malware - String Match in File - http://goo.gl/VRJNLo"
		author = "Florian Roth"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/06"
		score = 50
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = "cmd.exe /C FOR /L %%i IN (1,1,%d) DO IF EXIST"
		$a1 = "& SYSTEMINFO) ELSE EXIT"
		$mz = { 4d 5a }
		$c1 = "domcommon.exe" wide fullword
		$c2 = "jpic.gov.sy" fullword
		$c3 = "aiomgr.exe" wide fullword
		$c4 = "perfaudio.dat" fullword
		$c5 = "Casper_DLL.dll" fullword
		$c6 = { 7B 4B 59 DE 37 4A 42 26 59 98 63 C6 2D 0F 57 40 }
		$c7 = "{4216567A-4512-9825-7745F856}" fullword

	condition:
		all of ($a*) or ($mz at 0) and (1 of ($c*))
}
