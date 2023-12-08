rule Malware_QA_1177
{
	meta:
		description = "VT Research QA uploaded malware - file 1177.vbs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "ff3a2740330a6cbae7888e7066942b53015728c367cf9725e840af5b2a3fa247"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = ".specialfolders (\"startup\") & \"\\ServerName.EXE\"" fullword ascii
		$x2 = "expandenvironmentstrings(\"%%InsallDir%%\") " ascii
		$s1 = "CreateObject(\"WScript.Shell\").Run(" ascii
		$s2 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAA" ascii
		$s3 = "cial Thank's to Dev-point.com" fullword ascii
		$s4 = ".createElement(\"tmp\")" fullword ascii
		$s5 = "'%CopyToStartUp%" fullword ascii

	condition:
		( uint16(0)==0x4d27 and filesize <100KB and (1 of ($x*) or 4 of ($s*))) or (5 of them )
}
