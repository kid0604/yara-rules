rule CN_Honker_linux_bin
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file linux_bin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "26e71e6ebc6a3bdda9467ce929610c94de8a7ca0"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "client.sin_port = htons(atoi(argv[3]));" fullword ascii
		$s2 = "printf(\"\\n\\n*********Waiting Client connect*****\\n\\n\");" fullword ascii

	condition:
		filesize <20KB and all of them
}
