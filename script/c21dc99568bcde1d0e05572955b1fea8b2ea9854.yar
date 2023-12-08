rule phpshell17_php
{
	meta:
		description = "Semi-Auto-generated  - file phpshell17.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "9a928d741d12ea08a624ee9ed5a8c39d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" fullword
		$s1 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]<?php echo PHPSHELL_VERSION ?></"
		$s2 = "href=\"mailto: [YOU CAN ENTER YOUR MAIL HERE]- [ADDITIONAL TEXT]</a></i>" fullword

	condition:
		1 of them
}
