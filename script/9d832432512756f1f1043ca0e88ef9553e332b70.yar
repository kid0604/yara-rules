rule _r577_php_php_r57_php_php_spy_php_php_s_php_php
{
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash3 = "817671e1bdc85e04cc3440bbd9288800"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s0 = "$res = mssql_query(\"select * from r57_temp_table\",$db);" fullword
		$s2 = "'eng_text30'=>'Cat file'," fullword
		$s3 = "@mssql_query(\"drop table r57_temp_table\",$db);" fullword

	condition:
		1 of them
}
