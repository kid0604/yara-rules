import "pe"

rule DebuggerCheck__RemoteAPI : AntiDebug DebuggerCheck
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Detects the presence of remote debugger using CheckRemoteDebuggerPresent function"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "CheckRemoteDebuggerPresent"

	condition:
		any of them
}
