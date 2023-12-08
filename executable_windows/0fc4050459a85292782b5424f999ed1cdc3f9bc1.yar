rule glassRAT
{
	meta:
		author = "RSA RESEARCH"
		date = "3 Nov 2015"
		description = "Detects GlassRAT by RSA (modified by Florian Roth - speed improvements)"
		Info = "GlassRat"
		os = "windows"
		filetype = "executable"

	strings:
		$bin1 = {85 C0 B3 01}
		$bin3 = {68 4C 50 00 10}
		$bin4 = {68 48 50 00 10}
		$bin5 = {68 44 50 00 10}
		$hs = {CB FF 5D C9 AD 3F 5B A1 54 13 FE FB 05 C6 22}
		$s1 = "pwlfnn10,gzg"
		$s2 = "AddNum"
		$s3 = "ServiceMain"
		$s4 = "The Window"
		$s5 = "off.dat"

	condition:
		all of ($bin*) and $hs and 3 of ($s*)
}
