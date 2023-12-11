rule APT_NK_Scarcruft_evolved_ROKRAT
{
	meta:
		author = "S2WLAB_TALON_JACK2"
		description = "Detects RokRAT malware used by ScarCruft APT group"
		type = "APT"
		version = "0.1"
		date = "2021-07-09"
		reference = "https://medium.com/s2wlab/matryoshka-variant-of-rokrat-apt37-scarcruft-69774ea7bf48"
		os = "windows"
		filetype = "executable"

	strings:
		$AES_IV_KEY = {
        C7 44 24 ?? 32 31 12 23
        C7 44 24 ?? 34 45 56 67
        C7 44 24 ?? 78 89 9A AB
        C7 44 24 ?? 0C BD CE DF
        C7 45 ?? 2B 7E A5 16
        C7 45 ?? 28 AE D2 A6
        C7 45 ?? AB F7 15 88
        C7 45 ?? 09 CF 4F 3C
        }
		$url_deocde = {
               80 E9 0F
               80 F1 C8
               88 48 ??
               48 83 EA 01  }

	condition:
		uint16(0)==0x5A4D and any of them
}
