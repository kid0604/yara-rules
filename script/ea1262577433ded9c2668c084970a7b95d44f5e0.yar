rule CN_Honker_Webshell_nc_1
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file 1.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "51d83961171db000fe4476f36d703ef3de409676"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Mozilla/4.0 " ascii
		$s2 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii

	condition:
		filesize <11KB and all of them
}
