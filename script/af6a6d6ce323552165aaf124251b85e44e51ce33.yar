rule CN_Honker_Webshell_portRecall_jsp2
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jsp2.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "412ed15eb0d24298ba41731502018800ffc24bfc"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "final String remoteIP =request.getParameter(\"remoteIP\");" fullword ascii
		$s4 = "final String localIP = request.getParameter(\"localIP\");" fullword ascii
		$s20 = "final String localPort = \"3390\";//request.getParameter(\"localPort\");" fullword ascii

	condition:
		filesize <23KB and all of them
}
