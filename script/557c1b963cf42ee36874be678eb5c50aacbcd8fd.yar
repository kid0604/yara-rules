rule CN_Honker_Webshell_Linux_2_6_Exploit
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file 2.6.9"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ec22fac0510d0dc2c29d56c55ff7135239b0aeee"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "[+] Failed to get root :( Something's wrong.  Maybe the kernel isn't vulnerable?" fullword ascii

	condition:
		filesize <56KB and all of them
}
