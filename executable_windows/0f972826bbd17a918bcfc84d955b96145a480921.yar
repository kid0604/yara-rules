rule WindowsShell_Gen
{
	meta:
		description = "Detects simple Windows shell - from files keygen.exe, s1.exe, s2.exe, s3.exe, s4.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		super_rule = 1
		hash1 = "a7c3d85eabac01e7a7ec914477ea9f17e3020b3b2f8584a46a98eb6a2a7611c5"
		hash2 = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"
		hash3 = "df0693caae2e5914e63e9ee1a14c1e9506f13060faed67db5797c9e61f3907f0"
		hash4 = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		hash5 = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "[ %c%c requires parameter" fullword ascii
		$s1 = "[ %s : %i" fullword ascii
		$s2 = "[ %s : %s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <175KB and 2 of them ) or ( all of them )
}
