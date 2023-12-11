rule CN_Honker_Webshell_ASP_rootkit
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file rootkit.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3bfc1c95782e702cf56184e7d438edcf5802eab3"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "set ss=zsckm.get(\"Win32_ProcessSta\"&uyy&\"rtup\")" fullword ascii
		$s1 = "If jzgm=\"\"Then jzgm=\"cmd.exe /c net user\"" fullword ascii

	condition:
		filesize <80KB and all of them
}
