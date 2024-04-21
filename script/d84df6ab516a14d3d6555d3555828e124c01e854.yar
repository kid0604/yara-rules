rule SUSP_PY_Import_Statement_Apr24_1
{
	meta:
		description = "Detects suspicious Python import statement and socket usage often found in Python reverse shells"
		author = "Florian Roth"
		reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
		date = "2024-04-15"
		score = 65
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "import sys,socket,os,pty;s=socket.socket("

	condition:
		1 of them
}
