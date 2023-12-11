rule PHP_sh_alt_1
{
	meta:
		description = "Webshells Auto-generated - file sh.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1e9e879d49eb0634871e9b36f99fe528"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"

	condition:
		all of them
}
