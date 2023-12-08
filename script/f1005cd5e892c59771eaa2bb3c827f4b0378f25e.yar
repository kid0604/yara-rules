rule JspWebshell_1_2_jsp
{
	meta:
		description = "Semi-Auto-generated  - file JspWebshell 1.2.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "70a0ee2624e5bbe5525ccadc467519f6"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "JspWebshell"
		$s1 = "CreateAndDeleteFolder is error:"
		$s2 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.c"
		$s3 = "String _password =\"111\";"

	condition:
		2 of them
}
