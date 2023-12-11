rule APT34_Malware_HTA
{
	meta:
		description = "Detects APT 34 malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
		date = "2017-12-07"
		hash1 = "f6fa94cc8efea0dbd7d4d4ca4cf85ac6da97ee5cf0c59d16a6aafccd2b9d8b9a"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "WshShell.run \"cmd.exe /C C:\\ProgramData\\" ascii
		$x2 = ".bat&ping 127.0.0.1 -n 6 > nul&wscript  /b" ascii
		$x3 = "cmd.exe /C certutil -f  -decode C:\\ProgramData\\" ascii
		$x4 = "a.WriteLine(\"set Shell0 = CreateObject(" ascii
		$x5 = "& vbCrLf & \"Shell0.run" ascii
		$s1 = "<title>Blog.tkacprow.pl: HTA Hello World!</title>" fullword ascii
		$s2 = "<body onload=\"test()\">" fullword ascii

	condition:
		filesize <60KB and (1 of ($x*) or all of ($s*))
}
