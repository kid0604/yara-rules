rule FourElementSword_32DLL
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "7a200c4df99887991c638fe625d07a4a3fc2bdc887112437752b3df5c8da79b6"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%temp%\\tmp092.tmp" fullword ascii
		$s1 = "\\System32\\ctfmon.exe" ascii
		$s2 = "%SystemRoot%\\System32\\" ascii
		$s3 = "32.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <660KB and $x1) or ( all of them )
}
