rule FiveEyes_QUERTY_Malwaresig_20123_sys
{
	meta:
		description = "FiveEyes QUERTY Malware - file 20123.sys.bin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.spiegel.de/media/media-35668.pdf"
		date = "2015/01/18"
		hash = "a0f0087bd1f8234d5e847363d7e15be8a3e6f099"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "20123.dll" fullword ascii
		$s1 = "kbdclass.sys" fullword wide
		$s2 = "IoFreeMdl" fullword ascii
		$s3 = "ntoskrnl.exe" fullword ascii
		$s4 = "KfReleaseSpinLock" fullword ascii

	condition:
		all of them
}
