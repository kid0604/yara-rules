rule Pack_InjectT
{
	meta:
		description = "Webshells Auto-generated - file InjectT.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "983b74ccd57f6195a0584cdfb27d55e8"
		os = "windows"
		filetype = "executable"

	strings:
		$s3 = "ail To Open Registry"
		$s4 = "32fDssignim"
		$s5 = "vide Internet S"
		$s6 = "d]Software\\M"
		$s7 = "TInject.Dll"

	condition:
		all of them
}
