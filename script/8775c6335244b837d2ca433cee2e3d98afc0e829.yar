rule Msfpayloads_msf_6
{
	meta:
		description = "Metasploit Payloads - file msf.vbs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "8d6f55c6715c4a2023087c3d0d7abfa21e31a629393e4dc179d31bb25b166b3f"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
		$s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$s3 = ".GetSpecialFolder(2)" ascii
		$s4 = ".Write Chr(CLng(\"" ascii
		$s5 = "= \"4d5a90000300000004000000ffff00" ascii
		$s6 = "For i = 1 to Len(" ascii
		$s7 = ") Step 2" ascii

	condition:
		5 of them
}
