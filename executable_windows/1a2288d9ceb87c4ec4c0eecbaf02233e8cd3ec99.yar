rule Unpack_TBack
{
	meta:
		description = "Webshells Auto-generated - file TBack.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a9d1007823bf96fb163ab38726b48464"
		os = "windows"
		filetype = "executable"

	strings:
		$s5 = "\\final\\new\\lcc\\public.dll"

	condition:
		all of them
}
