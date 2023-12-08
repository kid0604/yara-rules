rule pws_php_php
{
	meta:
		description = "Semi-Auto-generated  - file pws.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ecdc6c20f62f99fa265ec9257b7bf2ce"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>" fullword
		$s1 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>" fullword
		$s4 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>"

	condition:
		2 of them
}
