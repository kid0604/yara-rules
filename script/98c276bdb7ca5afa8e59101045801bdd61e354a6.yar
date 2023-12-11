rule CN_Honker_Webshell_Serv_U_servu
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file servu.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7de701b86820096e486e64ca34f1fa9f2fbba641"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "fputs ($conn_id, \"SITE EXEC \".$dir.\"cmd.exe /c \".$cmd.\"\\r\\n\");" fullword ascii
		$s1 = "function ftpcmd($ftpport,$user,$password,$dir,$cmd){" fullword ascii

	condition:
		filesize <41KB and all of them
}
