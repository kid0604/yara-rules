import "pe"

rule APT28_SkinnyBoy_Dropper : RUSSIA
{
	meta:
		description = "Detects APT28 SkinnyBoy droppers"
		author = "Cluster25"
		date = "2021-05-24"
		reference = "https://cluster25.io/wp-content/uploads/2021/05/2021-05_FancyBear.pdf"
		hash1 = "12331809c3e03d84498f428a37a28cf6cbb1dafe98c36463593ad12898c588c9"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "cmd /c DEL " ascii
		$ = {8a 08 40 84 c9 75 f9}
		$ = {0f b7 84 0d fc fe ff ff 66 31 84 0d fc fd ff ff}

	condition:
		( uint16(0)==0x5A4D and all of them )
}
