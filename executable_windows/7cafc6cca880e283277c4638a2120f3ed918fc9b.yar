rule APT_MAL_CN_Wocao_checkadmin_bin
{
	meta:
		description = "Checkadmin utility"
		author = "Fox-IT SRT"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "[-] %s * A system error has occurred: %d" ascii wide
		$b = {
            0D 00 0A 00 25 00 6C 00 64 00 20 00 72 00 65 00
            73 00 75 00 6C 00 74 00 73 00 2E 00 0D 00 0A 00
        }
		$c = "%s\t<Access denied>" ascii wide

	condition:
		1 of them
}
