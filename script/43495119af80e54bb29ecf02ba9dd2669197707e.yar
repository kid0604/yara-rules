import "pe"

rule APT_Backdoor_PS1_BASICPIPESHELL_1
{
	meta:
		author = "FireEye"
		description = "Yara rule for detecting APT backdoor using PowerShell BasicPipeShell"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "function Invoke-Client()" ascii nocase wide
		$s2 = "function Invoke-Server" ascii nocase wide
		$s3 = "Read-Host 'Enter Command:'" ascii nocase wide
		$s4 = "new-object System.IO.Pipes.NamedPipeClientStream(" ascii nocase wide
		$s5 = "new-object System.IO.Pipes.NamedPipeServerStream(" ascii nocase wide
		$s6 = " = iex $" ascii nocase wide

	condition:
		all of them
}
