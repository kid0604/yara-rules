rule xssshell
{
	meta:
		description = "Webshells Auto-generated - file xssshell.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8fc0ffc5e5fbe85f7706ffc45b3f79b4"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma"

	condition:
		all of them
}
