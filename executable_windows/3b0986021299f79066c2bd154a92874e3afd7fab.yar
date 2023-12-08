rule Winnti_fonfig
{
	meta:
		description = "Winnti sample - file fonfig.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/VbvJtL"
		date = "2017-01-25"
		hash1 = "2c9882854a60c624ecf6b62b6c7cc7ed04cf4a29814aa5ed1f1a336854697641"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "mciqtz.exe" fullword wide
		$s2 = "knat9y7m" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
