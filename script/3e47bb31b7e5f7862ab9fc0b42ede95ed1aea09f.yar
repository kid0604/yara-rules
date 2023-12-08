rule WannCry_m_vbs
{
	meta:
		description = "Detects WannaCry Ransomware VBS"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/HG2j5T"
		date = "2017-05-12"
		hash1 = "51432d3196d9b78bdc9867a77d601caffd4adaa66dcac944a5ba0b3112bbea3b"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = ".TargetPath = \"C:\\@" ascii
		$x2 = ".CreateShortcut(\"C:\\@" ascii
		$s3 = " = WScript.CreateObject(\"WScript.Shell\")" ascii

	condition:
		( uint16(0)==0x4553 and filesize <1KB and all of them )
}
