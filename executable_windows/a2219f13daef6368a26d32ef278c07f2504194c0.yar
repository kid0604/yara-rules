import "pe"

rule DebuggerCheck__MemoryWorkingSet : AntiDebug DebuggerCheck
{
	meta:
		author = "Fernando Mercês"
		date = "2015-06"
		description = "Anti-debug process memory working set size check"
		reference = "http://www.gironsec.com/blog/2015/06/anti-debugger-trick-quicky/"
		os = "windows"
		filetype = "executable"

	condition:
		pe.imports("kernel32.dll","K32GetProcessMemoryInfo") and pe.imports("kernel32.dll","GetCurrentProcess")
}
