rule APT_MAL_CN_Wocao_injector_bin
{
	meta:
		description = "Process injector/launcher"
		author = "Fox-IT SRT"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "%s{%04d-%02d%02d-%02d%02d-%d%ld}.tmp"
		$b = "s% > s% c/ exe.d"
		$c = {
            48 89 5C 24 08 48 89 74  24 10 57 48 83 EC 50 48
            8B 71 08 48 8D 59 10 48  8B F9 48 8B CB FF 17 33
            C9 48 8D 47 78 48 89 44  24 48 4C 8D 87 9C 03 00
            00 48 89 5C 24 40 48 8D  97 90 00 00 00 4C 89 44
            24 38 45 33 C9 48 89 4C  24 30 45 33 C0 89 4C 24
            28 C7 44 24 20 01 00 00  00 66 89 4B 40 FF D6 48
            8B 5C 24 60 33 C0 48 8B  74 24 68 48 83 C4 50 5F
            C3
        }

	condition:
		1 of them
}
