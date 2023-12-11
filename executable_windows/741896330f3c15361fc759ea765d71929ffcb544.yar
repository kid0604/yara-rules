rule shelltools_g0t_root_xwhois
{
	meta:
		description = "Webshells Auto-generated - file xwhois.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "0bc98bd576c80d921a3460f8be8816b4"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "rting! "
		$s2 = "aTypCog("
		$s5 = "Diamond"
		$s6 = "r)r=rQreryr"

	condition:
		all of them
}
