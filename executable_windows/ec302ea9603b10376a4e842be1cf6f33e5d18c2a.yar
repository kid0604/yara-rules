rule _root_040_zip_Folder_deploy
{
	meta:
		description = "Webshells Auto-generated - file deploy.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "2c9f9c58999256c73a5ebdb10a9be269"
		os = "windows"
		filetype = "executable"

	strings:
		$s5 = "halon synscan 127.0.0.1 1-65536"
		$s8 = "Obviously you replace the ip address with that of the target."

	condition:
		all of them
}
