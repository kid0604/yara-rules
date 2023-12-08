rule malware_sakula_memory
{
	meta:
		description = "Sakula malware - strings after unpacking (memory rule)"
		author = "David Cannings"
		md5 = "b3852b9e7f2b8954be447121bb6b65c3"
		os = "windows"
		filetype = "executable"

	strings:
		$str01 = "cmd.exe /c ping 127.0.0.1 & del \"%s\""
		$str02 = "cmd.exe /c rundll32 \"%s\" Play \"%s\""
		$str03 = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+5.1;+SV1)"
		$str04 = "cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c \"%s\""
		$str05 = "Self Process Id:%d"
		$str06 = "%d_%d_%d_%s"
		$str07 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"
		$str08 = "cmd.exe /c rundll32 \"%s\" ActiveQvaw \"%s\""
		$opcodes01 = { 83 F9 00 74 0E 31 C0 8A 03 D0 C0 34 ?? 88 03 49 43 EB ED }
		$opcodes02 = { 31 C0 8A 04 13 32 01 83 F8 00 75 0E 83 FA 00 74 04 49 4A }

	condition:
		4 of them
}
