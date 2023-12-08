rule CobaltStrike_Resources_Template_x64_Ps1_v3_0_to_v4_x_excluding_3_12_3_13
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.hint.x64.ps1 and resources/template.hint.x32.ps1 from v3.0 to v4.x except 3.12 and 3.13"
		hash = "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "script"

	strings:
		$dda = "[AppDomain]::CurrentDomain.DefineDynamicAssembly" nocase
		$imm = "InMemoryModule" nocase
		$mdt = "MyDelegateType" nocase
		$rd = "New-Object System.Reflection.AssemblyName('ReflectedDelegate')" nocase
		$data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase
		$64bitSpecific = "[IntPtr]::size -eq 8"
		$mandatory = "Mandatory = $True"

	condition:
		all of them
}
