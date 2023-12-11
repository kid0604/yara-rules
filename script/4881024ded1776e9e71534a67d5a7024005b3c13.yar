import "math"
import "pe"

rule StoneDrill_VBS_1
{
	meta:
		description = "Detects malware from StoneDrill threat report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		date = "2017-03-07"
		hash1 = "0f4d608a87e36cb0dbf1b2d176ecfcde837070a2b2a049d532d3d4226e0c9587"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "wmic /NameSpace:\\\\root\\default Class StdRegProv Call SetStringValue hDefKey = \"&H80000001\" sSubKeyName = \"Software\\Micros" ascii
		$x2 = "ping 1.0.0.0 -n 1 -w 20000 > nul" fullword ascii
		$s1 = "WshShell.CopyFile \"%COMMON_APPDATA%\\Chrome\\" ascii
		$s2 = "WshShell.DeleteFile \"%temp%\\" ascii
		$s3 = "WScript.Sleep(10 * 1000)" fullword ascii
		$s4 = "Set WshShell = CreateObject(\"Scripting.FileSystemObject\") While WshShell.FileExists(\"" ascii
		$s5 = " , \"%COMMON_APPDATA%\\Chrome\\" ascii

	condition:
		( filesize <1KB and 1 of ($x*) or 2 of ($s*))
}
