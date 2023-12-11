rule webshell_r57shell127_r57_kartal_r57
{
	meta:
		description = "Web Shell - from files r57shell127.php, r57_kartal.php, r57.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae025c886fbe7f9ed159f49593674832"
		hash1 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash2 = "4108f28a9792b50d95f95b9e5314fa1e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "$handle = @opendir($dir) or die(\"Can't open directory $dir\");" fullword
		$s3 = "if(!empty($_POST['mysql_db'])) { @mssql_select_db($_POST['mysql_db'],$db); }" fullword
		$s5 = "if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!==$name || $_"

	condition:
		2 of them
}
