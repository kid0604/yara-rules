import "pe"

rule banbra : banker
{
	meta:
		author = "malware-lu"
		description = "Detects Banbra banker malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "senha" fullword nocase
		$b = "cartao" fullword nocase
		$c = "caixa"
		$d = "login" fullword nocase
		$e = ".com.br"

	condition:
		#a>3 and #b>3 and #c>3 and #d>3 and #e>3
}
