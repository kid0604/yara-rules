rule WannCry_BAT
{
	meta:
		description = "Detects WannaCry Ransomware BATCH File"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/HG2j5T"
		date = "2017-05-12"
		hash1 = "f01b7f52e3cb64f01ddc248eb6ae871775ef7cb4297eba5d230d0345af9a5077"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "@.exe\">> m.vbs" ascii
		$s2 = "cscript.exe //nologo m.vbs" fullword ascii
		$s3 = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> " ascii
		$s4 = "echo om.Save>> m.vbs" fullword ascii

	condition:
		( uint16(0)==0x6540 and filesize <1KB and 1 of them )
}
