rule trigger_drop
{
	meta:
		description = "Chinese Hacktool Set - file trigger_drop.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "165dd2d82bf87285c8a53ad1ede6d61a90837ba4"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s0 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
		$s1 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
		$s2 = "@mssql_query('DROP TRIGGER" ascii
		$s3 = "if(empty($_GET['returnto']))" fullword ascii

	condition:
		filesize <5KB and all of them
}
