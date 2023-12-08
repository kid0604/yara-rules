rule WebShell_Generic_PHP_7
{
	meta:
		description = "PHP Webshells Github Archive"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "de98f890790756f226f597489844eb3e53a867a9"
		hash1 = "128988c8ef5294d51c908690d27f69dffad4e42e"
		hash2 = "fd64f2bf77df8bcf4d161ec125fa5c3695fe1267"
		hash3 = "715f17e286416724e90113feab914c707a26d456"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "header(\"Content-disposition: filename=$filename.sql\");" fullword
		$s1 = "else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {" fullword
		$s2 = "echo \"<font color=blue>[$USERNAME]</font> - \\n\";" fullword
		$s4 = "if( $action == \"dumpTable\" )" fullword

	condition:
		2 of them
}
