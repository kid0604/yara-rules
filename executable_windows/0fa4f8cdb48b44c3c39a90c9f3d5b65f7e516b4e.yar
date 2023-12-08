import "pe"

rule gholeeV2
{
	meta:
		Author = "@GelosSnake"
		Date = "2015-02-12"
		Description = "Gholee first discovered variant "
		Reference = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html"
		description = "Detects Gholee first discovered variant"
		os = "windows"
		filetype = "executable"

	strings:
		$string0 = "RichHa"
		$string1 = "         (((((                  H" wide
		$string2 = "1$1,141<1D1L1T1\\1d1l1t1"
		$string3 = "<8;$O' "
		$string4 = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]"
		$string5 = "jYPQTVTSkllZTTXRTUiHceWda/"
		$string6 = "urn:schemas-microsoft-com:asm.v1"
		$string7 = "8.848H8O8i8s8y8"
		$string8 = "wrapper3" wide
		$string9 = "pwwwwwwww"
		$string10 = "Sunday"
		$string11 = "YYuTVWh"
		$string12 = "DDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN"
		$string13 = "ytMMMMMMUbbrrrrrxxxxxxxxrriUMMMMMMMMMUuzt"
		$string15 = "wrapper3 Version 1.0" wide
		$string16 = "77A779"
		$string17 = "<C<G<M<R<X<"
		$string18 = "9 9-9N9X9s9"

	condition:
		18 of them
}
