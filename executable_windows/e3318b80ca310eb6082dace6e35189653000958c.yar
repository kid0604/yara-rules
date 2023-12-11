rule Mithril_v1_45_dllTest
{
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
		os = "windows"
		filetype = "executable"

	strings:
		$s3 = "syspath"
		$s4 = "\\Mithril"
		$s5 = "--list the services in the computer"

	condition:
		all of them
}
