rule Universal_Exploit_Strings
{
	meta:
		description = "Detects a group of strings often used in exploit codes"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2017-12-02"
		score = 50
		hash1 = "9b07dacf8a45218ede6d64327c38478640ff17d0f1e525bd392c002e49fe3629"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "Exploit" fullword ascii
		$s2 = "Payload" fullword ascii
		$s3 = "CVE-201" ascii
		$s4 = "bindshell"

	condition:
		( filesize <2KB and 3 of them )
}
