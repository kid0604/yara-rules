import "pe"

rule ZxShell_Related_Malware_CN_Group_Jul17_3
{
	meta:
		description = "Detects a ZxShell related sample from a CN threat group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/cat-phishing/"
		date = "2017-07-08"
		hash1 = "2e5cf8c785dc081e5c2b43a4a785713c0ae032c5f86ccbc7abf5c109b8854ed7"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s\\nt%s.dll" fullword ascii
		$s2 = "RegQueryValueEx(Svchost\\netsvcs)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and all of them )
}
