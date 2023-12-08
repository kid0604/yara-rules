rule pwreveal
{
	meta:
		description = "Webshells Auto-generated - file pwreveal.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b4e8447826a45b76ca45ba151a97ad50"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "*<Blank - no es"
		$s3 = "JDiamondCS "
		$s8 = "sword set> [Leith=0 bytes]"
		$s9 = "ION\\System\\Floating-"

	condition:
		all of them
}
