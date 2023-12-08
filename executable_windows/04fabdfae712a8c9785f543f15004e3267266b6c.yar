rule p0wnedShellx64
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedShellx64.exe"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		modified = "2021-09-15"
		hash1 = "d8b4f5440627cf70fa0e0e19e0359b59e671885f8c1855517211ba331f48c449"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9Pjgb/+kPPhv9Sjp01Wf" wide
		$x2 = "Invoke-TokenManipulation" wide
		$x3 = "-CreateProcess \"cmd.exe\" -Username \"nt authority\\system\"" fullword wide
		$x4 = "CommandShell with Local Administrator privileges :)" fullword wide
		$x5 = "Invoke-shellcode -Payload windows/meterpreter/reverse_https -Lhost " fullword wide
		$fp1 = "AVSignature" ascii wide

	condition:
		1 of ($x*) and not 1 of them
}
