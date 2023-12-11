rule portlessinst
{
	meta:
		description = "Webshells Auto-generated - file portlessinst.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "74213856fc61475443a91cd84e2a6c2f"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "Fail To Open Registry"
		$s3 = "f<-WLEggDr\""
		$s6 = "oMemoryCreateP"

	condition:
		all of them
}
