rule ps1_toolkit_Invoke_RelfectivePEInjection
{
	meta:
		description = "Auto-generated rule - file Invoke-RelfectivePEInjection.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)" fullword ascii
		$x2 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local" fullword ascii
		$x3 = "} = Get-ProcAddress Advapi32.dll OpenThreadToken" ascii
		$x4 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local" fullword ascii
		$s5 = "$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')" fullword ascii
		$s6 = "= Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" ascii

	condition:
		( uint16(0)==0xbbef and filesize <700KB and 2 of them ) or ( all of them )
}
