rule Casper_Included_Strings
{
	meta:
		description = "Casper French Espionage Malware - String Match in File - http://goo.gl/VRJNLo"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/VRJNLo"
		date = "2015/03/06"
		score = 50
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = "cmd.exe /C FOR /L %%i IN (1,1,%d) DO IF EXIST"
		$a1 = "& SYSTEMINFO) ELSE EXIT"
		$c1 = "domcommon.exe" wide fullword
		$c2 = "jpic.gov.sy" fullword
		$c3 = "aiomgr.exe" wide fullword
		$c4 = "perfaudio.dat" fullword
		$c5 = "Casper_DLL.dll" fullword
		$c6 = { 7B 4B 59 DE 37 4A 42 26 59 98 63 C6 2D 0F 57 40 }
		$c7 = "{4216567A-4512-9825-7745F856}" fullword

	condition:
		all of ($a*) or uint16(0)==0x5a4d and (1 of ($c*))
}
