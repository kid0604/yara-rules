rule webshell_asp_up
{
	meta:
		description = "Web Shell - file up.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "f775e721cfe85019fe41c34f47c0d67c"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio"
		$s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword

	condition:
		1 of them
}
