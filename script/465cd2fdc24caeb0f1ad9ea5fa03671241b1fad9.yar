rule HYTop_DevPack_config
{
	meta:
		description = "Webshells Auto-generated - file config.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b41d0e64e64a685178a3155195921d61"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "const adminPassword=\""
		$s2 = "const userPassword=\""
		$s3 = "const mVersion="

	condition:
		all of them
}
