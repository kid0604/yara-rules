rule CN_Honker_Webshell_Tuoku_script_xx
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file xx.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2f39f1d9846ae72fc673f9166536dc21d8f396aa"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "$mysql.=\"insert into `$table`($keys) values($vals);\\r\\n\";" fullword ascii
		$s2 = "$mysql_link=@mysql_connect($mysql_servername , $mysql_username , $mysql_password" ascii
		$s16 = "mysql_query(\"SET NAMES gbk\");" fullword ascii

	condition:
		filesize <2KB and all of them
}
