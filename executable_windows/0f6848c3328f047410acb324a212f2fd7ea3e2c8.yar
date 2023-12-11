import "pe"

rule OilRig_Campaign_Reconnaissance
{
	meta:
		description = "Detects Windows discovery commands - known from OilRig Campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/QMRZ8K"
		date = "2016-10-12"
		hash1 = "5893eae26df8e15c1e0fa763bf88a1ae79484cdb488ba2fc382700ff2cfab80c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "whoami & hostname & ipconfig /all" ascii
		$s2 = "net user /domain 2>&1 & net group /domain 2>&1" ascii
		$s3 = "net group \"domain admins\" /domain 2>&1 & " ascii

	condition:
		( filesize <1KB and 1 of them )
}
