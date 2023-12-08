rule CN_Honker_Webshell_wshell_asp
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file wshell-asp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4a0afdf5a45a759c14e99eb5315964368ca53e9c"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "file1.Write(\"<%response.clear:execute request(\\\"root\\\"):response.End%>\");" fullword ascii
		$s2 = "hello word !  " fullword ascii
		$s3 = "root.asp " fullword ascii

	condition:
		filesize <5KB and all of them
}
