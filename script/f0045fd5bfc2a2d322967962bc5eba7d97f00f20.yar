rule TeleBots_VBS_Backdoor_1
{
	meta:
		description = "Detects TeleBots malware - VBS Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4if3HG"
		date = "2016-12-14"
		hash1 = "eb31a918ccc1643d069cf08b7958e2760e8551ba3b88ea9e5d496e07437273b2"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "cmd = \"cmd.exe /c \" + arg + \" >\" + outfile +\" 2>&1\"" fullword ascii
		$s2 = "GetTemp = \"c:\\WINDOWS\\addins\"" fullword ascii
		$s3 = "elseif (arg0 = \"-dump\") Then" fullword ascii
		$s4 = "decode = \"certutil -decode \" + source + \" \" + dest  " fullword ascii

	condition:
		( uint16(0)==0x6553 and filesize <8KB and 1 of them ) or ( all of them )
}
