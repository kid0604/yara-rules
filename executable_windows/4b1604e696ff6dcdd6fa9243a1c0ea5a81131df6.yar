rule CVE_2015_1674_CNGSYS
{
	meta:
		description = "Detects exploits for CVE-2015-1674"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.binvul.com/viewthread.php?tid=508"
		date = "2015-05-14"
		hash = "af4eb2a275f6bbc2bfeef656642ede9ce04fad36"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Device\\CNG" wide
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "LoadLibrary" ascii
		$s4 = "KERNEL32.dll" fullword ascii
		$s5 = "ntdll.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and all of them
}
