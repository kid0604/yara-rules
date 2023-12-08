rule Fireball_de_svr
{
	meta:
		description = "Detects Fireball malware - file de_svr.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		hash1 = "f964a4b95d5c518fd56f06044af39a146d84b801d9472e022de4c929a5b8fdcc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd.exe /c MD " fullword ascii
		$s2 = "rundll32.exe \"%s\",%s" fullword wide
		$s3 = "http://d12zpbetgs1pco.cloudfront.net/Weatherapi/shell" fullword wide
		$s4 = "C:\\v3\\exe\\de_svr_inst.pdb" fullword ascii
		$s5 = "Internet Connect Failed!" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <3000KB and 4 of them )
}
