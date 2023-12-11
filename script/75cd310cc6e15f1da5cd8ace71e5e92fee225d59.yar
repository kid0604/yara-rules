rule jsp_reverse_jsp_alt_1
{
	meta:
		description = "Semi-Auto-generated  - file jsp-reverse.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8b0e6779f25a17f0ffb3df14122ba594"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "// backdoor.jsp"
		$s1 = "JSP Backdoor Reverse Shell"
		$s2 = "http://michaeldaw.org"

	condition:
		2 of them
}
