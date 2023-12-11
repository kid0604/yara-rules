rule IronTiger_dnstunnel
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "This rule detects a dns tunnel tool used in Operation Iron Tiger"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "\\DnsTunClient\\" wide ascii
		$str2 = "\\t-DNSTunnel\\" wide ascii
		$str3 = "xssok.blogspot" wide ascii
		$str4 = "dnstunclient" wide ascii
		$mistake1 = "because of error, can not analysis" wide ascii
		$mistake2 = "can not deal witn the error" wide ascii
		$mistake3 = "the other retun one RST" wide ascii
		$mistake4 = "Coversation produce one error" wide ascii
		$mistake5 = "Program try to use the have deleted the buffer" wide ascii

	condition:
		( uint16(0)==0x5a4d) and (( any of ($str*)) or ( any of ($mistake*)))
}
