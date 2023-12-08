rule ELF_Linux_Torte_domains
{
	meta:
		author = "@mmorenog,@yararules"
		description = "Detects ELF Linux/Torte infection"
		ref1 = "http://blog.malwaremustdie.org/2016/01/mmd-0050-2016-incident-report-elf.html"
		os = "linux"
		filetype = "executable"

	strings:
		$1 = "pages.touchpadz.com" ascii wide nocase
		$2 = "bat.touchpadz.com" ascii wide nocase
		$3 = "stat.touchpadz.com" ascii wide nocase
		$4 = "sk2.touchpadz.com" ascii wide nocase

	condition:
		any of them
}
