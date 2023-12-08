rule CN_Honker_MatriXay1073
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file MatriXay1073.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		modified = "2023-01-27"
		score = 70
		hash = "fef951e47524f827c7698f4508ba9551359578a5"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1" ascii
		$s1 = "Policy\\Scan\\GetUserLen.ini" fullword ascii
		$s2 = "!YEL!Using http://127.0.0.1:%d/ to visiter https://%s:%d/" ascii
		$s3 = "getalluserpasswordhash" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <9100KB and all of them
}
