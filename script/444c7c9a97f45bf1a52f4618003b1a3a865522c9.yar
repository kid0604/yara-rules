rule CN_Honker_nc_MOVE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file MOVE.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4195370c103ca467cddc8f2724a8e477635be424"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "Destination: http://202.113.20.235/gj/images/2.asp" fullword ascii
		$s1 = "HOST: 202.113.20.235" fullword ascii
		$s2 = "MOVE /gj/images/A.txt HTTP/1.1" fullword ascii

	condition:
		filesize <1KB and all of them
}
