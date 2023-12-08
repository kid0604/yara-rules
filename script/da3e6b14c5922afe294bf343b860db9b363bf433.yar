rule SUSP_PY_Shell_Spawn_Jun23_1 : SCRIPT
{
	meta:
		description = "Detects suspicious one-liner to spawn a shell using Python"
		author = "Florian Roth"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		date = "2023-06-15"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "python -c import pty;pty.spawn(\"/bin/" ascii

	condition:
		1 of them
}
