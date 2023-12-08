rule Java_Shell_js
{
	meta:
		description = "Semi-Auto-generated  - file Java Shell.js.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "36403bc776eb12e8b7cc0eb47c8aac83"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "PySystemState.initialize(System.getProperties(), null, argv);" fullword
		$s3 = "public class JythonShell extends JPanel implements Runnable {" fullword
		$s4 = "public static int DEFAULT_SCROLLBACK = 100"

	condition:
		2 of them
}
