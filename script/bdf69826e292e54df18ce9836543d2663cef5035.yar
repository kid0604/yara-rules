rule CN_Honker_Webshell_offlibrary
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file offlibrary.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "eb5275f99211106ae10a23b7e565d208a94c402b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "';$i=$g->query(\"SELECT SUBSTRING_INDEX(CURRENT_USER, '@', 1) AS User, SUBSTRING" ascii
		$s12 = "if(jushRoot){var script=document.createElement('script');script.src=jushRoot+'ju" ascii

	condition:
		filesize <1005KB and all of them
}
