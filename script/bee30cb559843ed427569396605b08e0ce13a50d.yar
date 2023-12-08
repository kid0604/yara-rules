rule WebShell_php_webshells_tryag
{
	meta:
		description = "PHP Webshells Github Archive - file tryag.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "42d837e9ab764e95ed11b8bd6c29699d13fe4c41"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "<title>TrYaG Team - TrYaG.php - Edited By KingDefacer</title>" fullword
		$s3 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\"; " fullword
		$s6 = "$string = !empty($_POST['string']) ? $_POST['string'] : 0; " fullword
		$s7 = "$tabledump .= \"CREATE TABLE $table (\\n\"; " fullword
		$s14 = "echo \"<center><div id=logostrip>Edit file: $editfile </div><form action='$REQUE"

	condition:
		3 of them
}
