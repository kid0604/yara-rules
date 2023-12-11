rule BlackEnergy_VBS_Agent
{
	meta:
		description = "Detects VBS Agent from BlackEnergy Report - file Dropbearrun.vbs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2016-01-03"
		hash = "b90f268b5e7f70af1687d9825c09df15908ad3a6978b328dc88f96143a64af0f"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "WshShell.Run \"dropbear.exe -r rsa -d dss -a -p 6789\", 0, false" fullword ascii
		$s1 = "WshShell.CurrentDirectory = \"C:\\WINDOWS\\TEMP\\Dropbear\\\"" fullword ascii
		$s2 = "Set WshShell = CreateObject(\"WScript.Shell\")" fullword ascii

	condition:
		filesize <1KB and 2 of them
}
