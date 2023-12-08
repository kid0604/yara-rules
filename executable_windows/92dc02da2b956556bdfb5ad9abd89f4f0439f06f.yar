rule hkdoordll
{
	meta:
		description = "Webshells Auto-generated - file hkdoordll.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b715c009d47686c0e62d0981efce2552"
		os = "windows"
		filetype = "executable"

	strings:
		$s6 = "Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is"

	condition:
		all of them
}
