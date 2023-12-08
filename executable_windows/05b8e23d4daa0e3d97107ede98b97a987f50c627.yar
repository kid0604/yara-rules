rule CN_Honker_wwwscan_1_wwwscan
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wwwscan.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "6bed45629c5e54986f2d27cbfc53464108911026"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii
		$s3 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <180KB and all of them
}
