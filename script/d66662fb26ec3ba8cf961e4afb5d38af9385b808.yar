rule CN_Honker_portRecall_pr
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file pr"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "583cf6dc2304121d835f2879803a22fea76930f3"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "Usage: Same as lcx.exe in win32 :)" fullword ascii
		$s2 = "connect to client" fullword ascii
		$s3 = "PR(Packet redirection) for linux " fullword ascii

	condition:
		filesize <70KB and all of them
}
