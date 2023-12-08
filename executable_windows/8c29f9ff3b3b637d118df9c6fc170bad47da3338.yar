import "pe"

rule MALWARE_Win_CRATPluginRansomHansom
{
	meta:
		author = "ditekSHen"
		description = "Detects CRAT Hansom Ransomware plugin DLL"
		os = "windows"
		filetype = "executable"

	strings:
		$cmd1 = "/f /im \"%s\"" wide
		$cmd2 = "add HKLM\\%s /v %s /t REG_DWORD /d %d /F" wide
		$cmd3 = "add HKCU\\%s /v %s /t REG_DWORD /d %d /F" wide
		$cmd4 = "\"%s\" a -y -ep -k -r -s -ibck -df -m0 -hp%s -ri1:%d \"%s\" \"%s\"" wide
		$s1 = "\\hansom.jpg" wide
		$s2 = "HansomMain" fullword ascii wide
		$s3 = "ExtractHansom" fullword ascii wide
		$s4 = "Hansom2008" fullword ascii
		$s5 = ".hansomkey" fullword wide
		$s6 = ".hansom" fullword wide
		$s7 = /Ransom_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii

	condition:
		uint16(0)==0x5a4d and ((2 of ($cmd*) and 2 of ($s*)) or (4 of ($s*) and 1 of ($cmd*)) or 6 of them )
}
