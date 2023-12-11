rule TeleBots_VBS_Backdoor_2
{
	meta:
		description = "Detects TeleBots malware - VBS Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4if3HG"
		date = "2016-12-14"
		hash1 = "1b2a5922b58c8060844b43e14dfa5b0c8b119f281f54a46f0f1c34accde71ddb"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "cmd = \"cmd.exe /c \" + arg + \" \" + arg2" fullword ascii
		$s2 = "Dim WMI:  Set WMI = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")" fullword ascii
		$s3 = "cmd = \"certutil -encode -f \" + source + \" \" + dest" fullword ascii

	condition:
		( uint16(0)==0x6944 and filesize <30KB and 1 of them ) or (2 of them )
}
