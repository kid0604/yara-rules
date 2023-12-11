rule webshell_asp_ice
{
	meta:
		description = "Web Shell - file ice.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d141e011a92f48da72728c35f1934a2b"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC"

	condition:
		all of them
}
