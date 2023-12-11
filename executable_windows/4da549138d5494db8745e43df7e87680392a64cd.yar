import "pe"

rule ransom_telefonica : TELEF
{
	meta:
		author = "Jaume Martin <@Xumeiquer>"
		description = "Ransmoware Telefonica"
		date = "2017-05-13"
		reference = "http://www.elmundo.es/tecnologia/2017/05/12/59158a8ce5fdea194f8b4616.html"
		md5 = "7f7ccaa16fb15eb1c7399d422f8363e8"
		sha256 = "2584e1521065e45ec3c17767c065429038fc6291c091097ea8b22c8a502c41dd"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "RegCreateKeyW" wide ascii nocase
		$b = "cmd.exe /c"
		$c = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
		$d = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" ascii
		$e = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii
		$f = "tasksche.exe"

	condition:
		uint16(0)==0x5A4D and $a and for all of ($b,$c,$d,$e,$f) : (@>@a)
}
